// Package orphan provides filesystem reconciliation primitives that never
// expose or accept storage object names. Callers supply the authoritative set
// of tracked opaque objects for a single storage zone.
package orphan

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

var (
	ErrNotFound = errors.New("orphan object not found")
	ErrTooYoung = errors.New("orphan object is inside the reconciliation safety window")
)

type Candidate struct {
	Token         string    `json:"token"`
	Zone          string    `json:"zone"`
	Size          int64     `json:"size"`
	ModifiedAt    time.Time `json:"modifiedAt"`
	Eligible      bool      `json:"eligible"`
	Reason        string    `json:"reason"`
	StorageObject string    `json:"-"`
}

type ResumeOutcome struct {
	Status     string
	ReasonCode string
}

func List(root, zone string, tracked map[string]struct{}, minimumAge time.Duration, now time.Time) ([]Candidate, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	result := []Candidate{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if _, known := tracked[entry.Name()]; known {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		// Symbolic links and special files are never reconciliation candidates.
		// Following them could move deletion outside the configured storage root.
		if !info.Mode().IsRegular() {
			continue
		}
		// PostgreSQL timestamptz preserves microseconds. Normalizing here keeps
		// journal recovery comparisons stable across filesystems and restarts.
		modified := info.ModTime().UTC().Truncate(time.Microsecond)
		eligible := !modified.After(now.UTC().Add(-minimumAge))
		reason := "safety_window_active"
		if eligible {
			reason = "untracked_object"
		}
		result = append(result, Candidate{Token: token(zone, entry.Name(), info.Size(), modified), Zone: zone, Size: info.Size(), ModifiedAt: modified, Eligible: eligible, Reason: reason, StorageObject: entry.Name()})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ModifiedAt.Equal(result[j].ModifiedAt) {
			return result[i].Token < result[j].Token
		}
		return result[i].ModifiedAt.Before(result[j].ModifiedAt)
	})
	return result, nil
}

// Delete resolves an opaque preview token from a fresh directory scan and
// removes only the exact regular file whose attributes still match that token.
func Delete(root, zone string, tracked map[string]struct{}, requestedToken string, minimumAge time.Duration, now time.Time, isNowTracked func(string) (bool, error)) (Candidate, error) {
	candidates, err := List(root, zone, tracked, minimumAge, now)
	if err != nil {
		return Candidate{}, err
	}
	for _, candidate := range candidates {
		if candidate.Token != requestedToken {
			continue
		}
		if !candidate.Eligible {
			return Candidate{}, ErrTooYoung
		}
		if isNowTracked != nil {
			trackedNow, err := isNowTracked(candidate.StorageObject)
			if err != nil {
				return Candidate{}, err
			}
			if trackedNow {
				return Candidate{}, ErrNotFound
			}
		}
		path := filepath.Join(root, candidate.StorageObject)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != candidate.Size || !info.ModTime().UTC().Truncate(time.Microsecond).Equal(candidate.ModifiedAt) {
			return Candidate{}, ErrNotFound
		}
		if err := os.Remove(path); err != nil {
			return Candidate{}, err
		}
		candidate.StorageObject = ""
		return candidate, nil
	}
	return Candidate{}, ErrNotFound
}

// Resume completes a previously authorized deletion using only the exact
// object identity and attributes persisted in the durable journal. An absent
// object is success: it means deletion occurred before completion evidence was
// committed. Any changed or newly tracked object is retained fail closed.
func Resume(root, storageObject string, size int64, modifiedAt time.Time, isNowTracked func(string) (bool, error)) (ResumeOutcome, error) {
	if storageObject == "" || storageObject == "." || storageObject == ".." || filepath.Base(storageObject) != storageObject {
		return ResumeOutcome{Status: "failed", ReasonCode: "invalid_storage_identity"}, nil
	}
	if isNowTracked != nil {
		tracked, err := isNowTracked(storageObject)
		if err != nil {
			return ResumeOutcome{}, err
		}
		if tracked {
			return ResumeOutcome{Status: "failed", ReasonCode: "metadata_attached"}, nil
		}
	}
	path := filepath.Join(root, storageObject)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ResumeOutcome{Status: "completed", ReasonCode: "object_absent_after_authorization"}, nil
	}
	if err != nil {
		return ResumeOutcome{}, err
	}
	if !info.Mode().IsRegular() || info.Size() != size || !info.ModTime().UTC().Truncate(time.Microsecond).Equal(modifiedAt.UTC().Truncate(time.Microsecond)) {
		return ResumeOutcome{Status: "failed", ReasonCode: "revalidation_failed"}, nil
	}
	if err := os.Remove(path); err != nil {
		return ResumeOutcome{}, err
	}
	return ResumeOutcome{Status: "completed", ReasonCode: "untracked_object_removed"}, nil
}

func token(zone, name string, size int64, modified time.Time) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(zone))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(name))
	var numeric [8]byte
	binary.BigEndian.PutUint64(numeric[:], uint64(size))
	_, _ = hash.Write(numeric[:])
	binary.BigEndian.PutUint64(numeric[:], uint64(modified.UTC().UnixNano()))
	_, _ = hash.Write(numeric[:])
	return "orp_" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
