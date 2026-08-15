package orphan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListAndDeleteEnforceTrackingAgeAndRevalidation(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, time.August, 13, 20, 0, 0, 0, time.UTC)
	old := now.Add(-2 * time.Hour)
	writeObject := func(name, content string, modified time.Time) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
		return path
	}
	writeObject("tracked.upload", "tracked", old)
	oldPath := writeObject("opaque-old.upload", "old orphan", old)
	writeObject("opaque-fresh.upload", "fresh orphan", now.Add(-10*time.Minute))
	if err := os.Mkdir(filepath.Join(root, "not-an-object"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Symlink creation may require an elevated Windows developer setting. When
	// available, include one and prove it is ignored as a non-regular object.
	_ = os.Symlink(oldPath, filepath.Join(root, "object-link"))
	tracked := map[string]struct{}{"tracked.upload": {}}

	candidates, err := List(root, "quarantine", tracked, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("unexpected candidate count: %#v", candidates)
	}
	var eligible, fresh Candidate
	for _, candidate := range candidates {
		if strings.Contains(candidate.Token, "opaque") {
			t.Fatal("token exposed an object name")
		}
		if candidate.Eligible {
			eligible = candidate
		} else {
			fresh = candidate
		}
	}
	if eligible.Token == "" || fresh.Reason != "safety_window_active" {
		t.Fatalf("age policy was inaccurate: %#v", candidates)
	}
	if _, err := Delete(root, "quarantine", tracked, fresh.Token, time.Hour, now, nil); !errors.Is(err, ErrTooYoung) {
		t.Fatalf("fresh orphan deletion returned %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "tracked.upload")); err != nil {
		t.Fatal("tracked object was touched")
	}

	// Any change after preview creates a different token and invalidates the
	// operation, even if the storage object name remains the same.
	if err := os.WriteFile(oldPath, []byte("changed after preview"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(root, "quarantine", tracked, eligible.Token, time.Hour, now, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale preview was accepted: %v", err)
	}
}

func TestDeleteBlocksLastMomentTrackingAndRemovesOnlyExactCandidate(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	path := filepath.Join(root, "opaque.ciphertext")
	if err := os.WriteFile(path, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	candidates, err := List(root, "protected", map[string]struct{}{}, time.Hour, now)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("preview failed: %#v %v", candidates, err)
	}
	if _, err := Delete(root, "protected", map[string]struct{}{}, candidates[0].Token, time.Hour, now, func(string) (bool, error) { return true, nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("last-moment metadata match did not block deletion: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("revalidated tracked object was removed")
	}
	deleted, err := Delete(root, "protected", map[string]struct{}{}, candidates[0].Token, time.Hour, now, func(string) (bool, error) { return false, nil })
	if err != nil || deleted.Token != candidates[0].Token {
		t.Fatalf("eligible deletion failed: %#v %v", deleted, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan remained after deletion: %v", err)
	}
}

func TestResumeHandlesBothCrashWindowsAndFailsClosed(t *testing.T) {
	root := t.TempDir()
	modified := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	write := func(name, contents string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
		return path
	}

	path := write("authorized.upload", "pending")
	outcome, err := Resume(root, filepath.Base(path), int64(len("pending")), modified, func(string) (bool, error) { return false, nil })
	if err != nil || outcome.Status != "completed" || outcome.ReasonCode != "untracked_object_removed" {
		t.Fatalf("authorized object was not resumed: %#v %v", outcome, err)
	}
	// A crash after removal but before journal completion is repaired as success.
	outcome, err = Resume(root, filepath.Base(path), int64(len("pending")), modified, nil)
	if err != nil || outcome.Status != "completed" || outcome.ReasonCode != "object_absent_after_authorization" {
		t.Fatalf("absent authorized object was not repaired: %#v %v", outcome, err)
	}

	trackedPath := write("newly-tracked.upload", "tracked")
	outcome, err = Resume(root, filepath.Base(trackedPath), int64(len("tracked")), modified, func(string) (bool, error) { return true, nil })
	if err != nil || outcome.Status != "failed" || outcome.ReasonCode != "metadata_attached" {
		t.Fatalf("new tracking did not fail closed: %#v %v", outcome, err)
	}
	if _, err := os.Stat(trackedPath); err != nil {
		t.Fatal("newly tracked object was removed")
	}
	if outcome, err := Resume(root, "../outside", 1, modified, nil); err != nil || outcome.ReasonCode != "invalid_storage_identity" {
		t.Fatalf("unsafe storage identity was accepted: %#v %v", outcome, err)
	}
}
