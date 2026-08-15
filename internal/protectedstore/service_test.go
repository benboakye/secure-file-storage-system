package protectedstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"securestore/internal/auditoutbox"
	"securestore/internal/orphan"
)

func TestOrphanReconciliationJournalRepairsMissingCompletion(t *testing.T) {
	service, _, root := newTestService(t)
	modified := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	object := "untracked.ciphertext"
	path := filepath.Join(root, object)
	if err := os.WriteFile(path, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	candidate := orphan.Candidate{Token: "orp_test", Zone: "protected", StorageObject: object, Size: int64(len("ciphertext")), ModifiedAt: modified, Eligible: true}
	operation, created, err := service.AuthorizeOrphanReconciliation(candidate, "admin-1", "corr-1", auditoutbox.Intent{})
	if err != nil || !created || operation.Status != ReconciliationAuthorized {
		t.Fatalf("authorization was not journaled: %#v %v", operation, err)
	}
	duplicate, created, err := service.AuthorizeOrphanReconciliation(candidate, "admin-1", "corr-2", auditoutbox.Intent{})
	if err != nil || created || duplicate.OperationID != operation.OperationID {
		t.Fatalf("token idempotency failed: %#v %v", duplicate, err)
	}
	// Simulate the precise crash window: filesystem removal succeeded but the
	// completion transaction never ran.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	pending, err := service.PendingOrphanReconciliations(25)
	if err != nil || len(pending) != 1 {
		t.Fatalf("authorized operation was not recoverable: %#v %v", pending, err)
	}
	outcome, err := service.ResumeProtectedOrphan(pending[0])
	if err != nil || outcome.ReasonCode != "object_absent_after_authorization" {
		t.Fatalf("crash window was not recognized: %#v %v", outcome, err)
	}
	updated, err := service.CompleteOrphanReconciliation(operation.OperationID, outcome.Status, outcome.ReasonCode, auditoutbox.Intent{})
	if err != nil || !updated {
		t.Fatalf("completion was not committed: %v %v", updated, err)
	}
	pending, err = service.PendingOrphanReconciliations(25)
	if err != nil || len(pending) != 0 {
		t.Fatalf("completed operation remained pending: %#v %v", pending, err)
	}
}

func TestProtectOpenIsIdempotentAndRemainsOpaque(t *testing.T) {
	service, repository, root := newTestService(t)
	plaintext := []byte("authenticated protected content")
	digest := sha256.Sum256(plaintext)
	request := Request{UploadID: "upl_test", OwnerID: "usr_owner", PlaintextSize: int64(len(plaintext)), PlaintextDigest: hex.EncodeToString(digest[:]), MediaType: "text/plain", InspectionRecordID: "upl_test"}
	first, err := service.Protect(t.Context(), request, bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Protect(t.Context(), request, bytes.NewReader([]byte("different")))
	if err != nil || second.VersionID != first.VersionID {
		t.Fatalf("idempotent protection failed: %#v %v", second, err)
	}
	opened, err := service.Open("usr_owner", "upl_test")
	if err != nil || !bytes.Equal(opened.Bytes, plaintext) {
		t.Fatalf("protected round trip failed: %v", err)
	}
	if _, err := service.Open("usr_other", "upl_test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner open returned %v", err)
	}
	stored, _ := repository.FindByUpload("usr_owner", "upl_test")
	ciphertext, err := os.ReadFile(filepath.Join(root, stored.BlobObject))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, plaintext) || stored.BlobObject == "upl_test" {
		t.Fatal("protected object exposed plaintext or predictable upload locator")
	}
}

func TestOpenRejectsCiphertextAndAADMutation(t *testing.T) {
	service, repository, root := newTestService(t)
	plaintext := []byte("integrity-bound content")
	digest := sha256.Sum256(plaintext)
	request := Request{UploadID: "upl_tamper", OwnerID: "usr_owner", PlaintextSize: int64(len(plaintext)), PlaintextDigest: hex.EncodeToString(digest[:]), MediaType: "text/plain", InspectionRecordID: "upl_tamper"}
	metadata, err := service.Protect(t.Context(), request, bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, metadata.BlobObject)
	ciphertext, _ := os.ReadFile(path)
	ciphertext[len(ciphertext)-1] ^= 0x01
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Open("usr_owner", "upl_tamper"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("ciphertext mutation returned %v", err)
	}
	stored := repository.entries["upl_tamper"]
	stored.MediaType = "application/pdf"
	repository.entries["upl_tamper"] = stored
	if _, err := service.Open("usr_owner", "upl_tamper"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("AAD mutation returned %v", err)
	}
}

func TestRepeatedPlaintextProducesDifferentCiphertext(t *testing.T) {
	service, _, root := newTestService(t)
	plaintext := []byte("same content")
	digest := sha256.Sum256(plaintext)
	makeRequest := func(id string) Request {
		return Request{UploadID: id, OwnerID: "usr_owner", PlaintextSize: int64(len(plaintext)), PlaintextDigest: hex.EncodeToString(digest[:]), MediaType: "text/plain", InspectionRecordID: id}
	}
	a, _ := service.Protect(t.Context(), makeRequest("upl_a"), bytes.NewReader(plaintext))
	b, _ := service.Protect(t.Context(), makeRequest("upl_b"), bytes.NewReader(plaintext))
	left, _ := os.ReadFile(filepath.Join(root, a.BlobObject))
	right, _ := os.ReadFile(filepath.Join(root, b.BlobObject))
	if bytes.Equal(left, right) {
		t.Fatal("fresh DEKs/nonces did not produce distinct ciphertext")
	}
}

func TestCapacitySummaryReconcilesTrackedOrphanedAndMissingObjects(t *testing.T) {
	service, _, root := newTestService(t)
	plaintext := []byte("capacity evidence")
	digest := sha256.Sum256(plaintext)
	metadata, err := service.Protect(t.Context(), Request{UploadID: "upl_capacity", OwnerID: "usr_owner", PlaintextSize: int64(len(plaintext)), PlaintextDigest: hex.EncodeToString(digest[:]), MediaType: "text/plain", InspectionRecordID: "upl_capacity"}, bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	orphan := []byte("unmatched ciphertext")
	if err := os.WriteFile(filepath.Join(root, "orphan.ciphertext"), orphan, 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := service.CapacitySummary()
	if err != nil {
		t.Fatal(err)
	}
	if summary.TrackedObjects != 1 || summary.TrackedCiphertextBytes != int64(len(plaintext)+16) {
		t.Fatalf("tracked ciphertext was not measured from disk: %#v", summary)
	}
	if summary.OrphanedObjects != 1 || summary.OrphanedBytes != int64(len(orphan)) || summary.MissingObjects != 0 {
		t.Fatalf("protected reconciliation was incorrect: %#v", summary)
	}
	if summary.VolumeTotalBytes == 0 || summary.VolumeAvailableBytes == 0 {
		t.Fatalf("hosting volume capacity was not reported: %#v", summary)
	}
	if err := os.Remove(filepath.Join(root, metadata.BlobObject)); err != nil {
		t.Fatal(err)
	}
	summary, err = service.CapacitySummary()
	if err != nil {
		t.Fatal(err)
	}
	if summary.MissingObjects != 1 {
		t.Fatalf("missing protected object was not detected: %#v", summary)
	}
}

func TestRestoreCreatesNewImmutableEncryptedVersion(t *testing.T) {
	service, repository, root := newTestService(t)
	plaintext := []byte("immutable version source")
	digest := sha256.Sum256(plaintext)
	metadata, err := service.Protect(t.Context(), Request{UploadID: "upl_catalog", OwnerID: "usr_owner", PlaintextSize: int64(len(plaintext)), PlaintextDigest: hex.EncodeToString(digest[:]), MediaType: "text/plain", InspectionRecordID: "upl_catalog"}, bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	file, initial, err := service.RegisterInitial("usr_owner", "history.txt", metadata)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := service.Restore(t.Context(), "usr_owner", file.FileID, initial.VersionID, "restore-test-key")
	if err != nil {
		t.Fatal(err)
	}
	if restored.Number != 2 || restored.VersionID == initial.VersionID || restored.SourceVersionID != initial.VersionID {
		t.Fatalf("unexpected restored version: %#v", restored)
	}
	retry, err := service.Restore(t.Context(), "usr_owner", file.FileID, initial.VersionID, "restore-test-key")
	if err != nil || retry.VersionID != restored.VersionID {
		t.Fatalf("restore retry was not idempotent: %#v %v", retry, err)
	}
	details, err := service.Details("usr_owner", file.FileID)
	if err != nil || len(details.Versions) != 2 || !details.Versions[0].Current || details.Versions[1].Current {
		t.Fatalf("invalid immutable history: %#v %v", details, err)
	}
	current, err := service.OpenCurrent("usr_owner", file.FileID)
	if err != nil || !bytes.Equal(current.Bytes, plaintext) {
		t.Fatalf("restored content mismatch: %v", err)
	}
	sourceMetadata, _ := repository.FindVersion("usr_owner", file.FileID, initial.VersionID)
	restoredMetadata, _ := repository.FindVersion("usr_owner", file.FileID, restored.VersionID)
	sourceCiphertext, _ := os.ReadFile(filepath.Join(root, sourceMetadata.BlobObject))
	restoredCiphertext, _ := os.ReadFile(filepath.Join(root, restoredMetadata.BlobObject))
	if bytes.Equal(sourceCiphertext, restoredCiphertext) {
		t.Fatal("restore reused the source ciphertext")
	}
	if _, err := service.Details("usr_other", file.FileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner details returned %v", err)
	}
}

func TestAccessGrantEnforcesCapabilityExpiryAndRevocation(t *testing.T) {
	service, _, _ := newTestService(t)
	plaintext := []byte("grant protected content")
	digest := sha256.Sum256(plaintext)
	metadata, err := service.Protect(t.Context(), Request{UploadID: "upl_grant", OwnerID: "usr_owner", PlaintextSize: int64(len(plaintext)), PlaintextDigest: hex.EncodeToString(digest[:]), MediaType: "text/plain", InspectionRecordID: "upl_grant"}, bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := service.RegisterInitial("usr_owner", "grant.txt", metadata)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.CreateGrant("usr_owner", file.FileID, Recipient{ID: "usr_reader", Name: "Read User", Email: "reader@example.test"}, PermissionRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthorizedDetails("usr_reader", file.FileID); err != nil {
		t.Fatalf("read grant denied metadata: %v", err)
	}
	if _, err := service.OpenCurrentAuthorized("usr_reader", file.FileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read-only grant downloaded content: %v", err)
	}
	updated, err := service.CreateGrant("usr_owner", file.FileID, Recipient{ID: "usr_reader", Name: "Read User", Email: "reader@example.test"}, PermissionDownload, nil)
	if err != nil || updated.GrantID != grant.GrantID {
		t.Fatalf("grant update was not stable: %#v %v", updated, err)
	}
	opened, err := service.OpenCurrentAuthorized("usr_reader", file.FileID)
	if err != nil || !bytes.Equal(opened.Bytes, plaintext) {
		t.Fatalf("download grant failed: %v", err)
	}
	if err := service.RevokeGrant("usr_owner", file.FileID, grant.GrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthorizedDetails("usr_reader", file.FileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked grant retained access: %v", err)
	}
	expires := time.Now().UTC().Add(15 * time.Millisecond)
	if _, err := service.CreateGrant("usr_owner", file.FileID, Recipient{ID: "usr_expiring", Name: "Expiry User", Email: "expiry@example.test"}, PermissionDownload, &expires); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := service.OpenCurrentAuthorized("usr_expiring", file.FileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired grant retained access: %v", err)
	}
}

func TestTrashRetentionHoldRestoreAndCryptographicPurge(t *testing.T) {
	service, repository, root := newTestService(t)
	plaintext := []byte("lifecycle protected content")
	digest := sha256.Sum256(plaintext)
	metadata, err := service.Protect(t.Context(), Request{UploadID: "upl_lifecycle", OwnerID: "usr_owner", PlaintextSize: int64(len(plaintext)), PlaintextDigest: hex.EncodeToString(digest[:]), MediaType: "text/plain", InspectionRecordID: "upl_lifecycle"}, bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := service.RegisterInitial("usr_owner", "lifecycle.txt", metadata)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	retention := now.Add(24 * time.Hour)
	if _, err := service.SetRetention(file.FileID, &retention); err != nil {
		t.Fatal(err)
	}
	if _, err := service.MoveToTrash("usr_owner", file.FileID); !errors.Is(err, ErrRetentionActive) {
		t.Fatalf("retention did not block trash: %v", err)
	}
	if _, err := service.SetLegalHold(file.FileID, true, "Active litigation matter"); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return retention.Add(time.Second) }
	if _, err := service.MoveToTrash("usr_owner", file.FileID); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("legal hold did not block trash: %v", err)
	}
	if _, err := service.SetLegalHold(file.FileID, false, ""); err != nil {
		t.Fatal(err)
	}
	trashed, err := service.MoveToTrash("usr_owner", file.FileID)
	if err != nil {
		t.Fatal(err)
	}
	if trashed.PurgeAfter == nil || len(mustTrash(t, service, "usr_owner")) != 1 {
		t.Fatal("trash lifecycle was not recorded")
	}
	if _, err := service.AuthorizedDetails("usr_owner", file.FileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("trashed owner access remained available: %v", err)
	}
	if _, err := service.RestoreFromTrash("usr_owner", file.FileID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthorizedDetails("usr_owner", file.FileID); err != nil {
		t.Fatalf("restored file unavailable: %v", err)
	}
	trashed, err = service.MoveToTrash("usr_owner", file.FileID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Purge("usr_owner", file.FileID, "purge-test-key"); !errors.Is(err, ErrPurgeTooEarly) {
		t.Fatalf("grace period did not block purge: %v", err)
	}
	extendedRetention := trashed.PurgeAfter.Add(24 * time.Hour)
	if _, err := service.SetRetention(file.FileID, &extendedRetention); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return trashed.PurgeAfter.Add(time.Second) }
	if _, err := service.Purge("usr_owner", file.FileID, "purge-test-key"); !errors.Is(err, ErrRetentionActive) {
		t.Fatalf("retention did not block cryptographic purge: %v", err)
	}
	if _, err := service.SetLegalHold(file.FileID, true, "Post-trash litigation hold"); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return extendedRetention.Add(time.Second) }
	if _, err := service.Purge("usr_owner", file.FileID, "purge-test-key"); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("legal hold did not block cryptographic purge: %v", err)
	}
	if _, err := service.SetLegalHold(file.FileID, false, ""); err != nil {
		t.Fatal(err)
	}
	result, err := service.Purge("usr_owner", file.FileID, "purge-test-key")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := service.Purge("usr_owner", file.FileID, "purge-test-key")
	if err != nil || retry.OperationID != result.OperationID {
		t.Fatalf("purge retry was not idempotent: %#v %v", retry, err)
	}
	if result.DestroyedKeys != 1 || len(repository.entries["upl_lifecycle"].WrappedDEK) != 0 {
		t.Fatalf("wrapped key was not destroyed: %#v", result)
	}
	if _, err := os.Stat(filepath.Join(root, metadata.BlobObject)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext cleanup did not complete: %v", err)
	}
}

func TestScheduledPurgeAndMetadataOnlyRecoveryDrill(t *testing.T) {
	service, repository, _ := newTestService(t)
	plaintext := []byte("recovery assurance content")
	digest := sha256.Sum256(plaintext)
	metadata, err := service.Protect(t.Context(), Request{UploadID: "upl_assurance", OwnerID: "usr_owner", PlaintextSize: int64(len(plaintext)), PlaintextDigest: hex.EncodeToString(digest[:]), MediaType: "text/plain", InspectionRecordID: "upl_assurance"}, bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := service.RegisterInitial("usr_owner", "assurance.txt", metadata)
	if err != nil {
		t.Fatal(err)
	}

	drill, err := service.RunRecoveryDrill(file.FileID, "usr_admin")
	if err != nil || drill.Outcome != "verified" || drill.VersionID != metadata.VersionID {
		t.Fatalf("recovery drill did not verify the encrypted version: %#v %v", drill, err)
	}
	if len(repository.drills) != 1 {
		t.Fatal("recovery evidence was not recorded")
	}

	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	trashed, err := service.MoveToTrash("usr_owner", file.FileID)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return trashed.PurgeAfter.Add(time.Second) }
	result := service.ProcessDuePurges(25)
	if result.Examined != 1 || result.Completed != 1 || result.Failed != 0 {
		t.Fatalf("unexpected worker result: %#v", result)
	}
	retry := service.ProcessDuePurges(25)
	if retry.Examined != 0 || len(repository.deletions) != 1 {
		t.Fatalf("completed work was not idempotent: %#v", retry)
	}
}

func TestDEKRewrapPreservesCiphertextAndRemovesHistoricalKEKDependency(t *testing.T) {
	root := t.TempDir()
	repository := NewMemoryRepository()
	v1Key, v2Key := bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32)
	v1, err := NewLocalKeyringProvider(map[string][]byte{"v1": v1Key}, "test-kek", "v1")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(Config{RootDir: root, MaxPlaintextBytes: 1024, Repository: repository, Keys: v1})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("ciphertext remains immutable during wrapper rotation")
	digest := sha256.Sum256(plaintext)
	metadata, err := service.Protect(t.Context(), Request{UploadID: "upl_rewrap", OwnerID: "usr_owner", PlaintextSize: int64(len(plaintext)), PlaintextDigest: hex.EncodeToString(digest[:]), MediaType: "text/plain", InspectionRecordID: "inspection_rewrap"}, bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, metadata.BlobObject)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	v2, err := NewLocalKeyringProvider(map[string][]byte{"v1": v1Key, "v2": v2Key}, "test-kek", "v2")
	if err != nil {
		t.Fatal(err)
	}
	service.keys = v2
	result, err := service.RewrapDEKs(10, func(value Metadata, fromID, fromVersion, toID, toVersion string) (auditoutbox.Intent, error) {
		return auditoutbox.Intent{EventID: "evt_rewrap", OccurredAt: time.Now().UTC(), ActorType: "user", ActorID: "admin_test", Action: "FILE_DEK_REWRAPPED", ResourceType: "file_version", ResourceID: value.VersionID, Outcome: "success", ReasonCode: "administrator_key_rotation", FromState: fromID + ":" + fromVersion, ToState: toID + ":" + toVersion}, nil
	})
	if err != nil || result.Completed != 1 || result.Remaining != 0 {
		t.Fatalf("rewrap failed: %#v %v", result, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("DEK rewrap modified protected ciphertext")
	}
	stored, err := repository.FindByUpload("usr_owner", "upl_rewrap")
	if err != nil || stored.KEKVersion != "v1" || stored.WrappingKEKVersion != "v2" {
		t.Fatalf("key identities were not separated: %#v %v", stored, err)
	}

	// Prove the historical wrapping key can be retired after the batch while the
	// original authenticated envelope metadata remains unchanged.
	v2Only, err := NewLocalKeyringProvider(map[string][]byte{"v2": v2Key}, "test-kek", "v2")
	if err != nil {
		t.Fatal(err)
	}
	service.keys = v2Only
	opened, err := service.Open("usr_owner", "upl_rewrap")
	if err != nil || !bytes.Equal(opened.Bytes, plaintext) {
		t.Fatalf("rewrapped file requires retired KEK: %v", err)
	}
}

func mustTrash(t *testing.T, service *Service, ownerID string) []LifecycleFile {
	t.Helper()
	files, err := service.ListTrash(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func newTestService(t *testing.T) (*Service, *MemoryRepository, string) {
	t.Helper()
	root := t.TempDir()
	repository := NewMemoryRepository()
	keys, err := NewLocalKeyProvider(bytes.Repeat([]byte{0x41}, 32), "local-test", "v1")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(Config{RootDir: root, MaxPlaintextBytes: 1024, Repository: repository, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return service, repository, root
}
