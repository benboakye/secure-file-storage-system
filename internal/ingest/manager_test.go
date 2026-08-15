package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"securestore/internal/auditoutbox"
	"securestore/internal/protectedstore"
)

type gatedScanner struct{ release <-chan struct{} }

func (scanner gatedScanner) Inspect(ctx context.Context, _ Evidence) (ScanResult, error) {
	select {
	case <-scanner.release:
		return ScanResult{Accepted: true, Reason: "clean", Tool: "test", Policy: "test"}, nil
	case <-ctx.Done():
		return ScanResult{}, ctx.Err()
	}
}

func TestLifecycleOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		fileName   string
		wantStatus Status
	}{
		{name: "accepted", fileName: "training.pdf", wantStatus: StatusAccepted},
		{name: "rejected", fileName: "blocked-sample.exe", wantStatus: StatusRejected},
		{name: "fail closed", fileName: "scanner-error.pdf", wantStatus: StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := newTestManager(t, 1024)
			upload, reused, err := manager.Create(t.Context(), "usr_1", "idem-key-123", test.fileName, "application/pdf", bytes.NewBufferString("harmless fixture"))
			if err != nil || reused {
				t.Fatalf("create failed: reused=%v err=%v", reused, err)
			}
			terminal := waitForTerminal(t, manager, "usr_1", upload.ID)
			if terminal.Status != test.wantStatus || terminal.Progress != 100 {
				t.Fatalf("unexpected terminal state: %#v", terminal)
			}
		})
	}
}

func TestUploadLimitIdempotencyAndOpaquePath(t *testing.T) {
	directory := t.TempDir()
	manager, err := NewManager(Config{
		QuarantineDir: directory, MaxUploadBytes: 16,
		InspectionTTL: time.Second, Scanner: DeterministicScanner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Create(t.Context(), "usr_1", "idem-large-1", "large.txt", "text/plain", strings.NewReader(strings.Repeat("a", 17))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized upload returned %v", err)
	}

	upload, reused, err := manager.Create(t.Context(), "usr_1", "idem-safe-1", "../../report.txt", "text/plain", strings.NewReader("safe"))
	if err != nil || reused {
		t.Fatalf("first upload failed: %v", err)
	}
	duplicate, reused, err := manager.Create(t.Context(), "usr_1", "idem-safe-1", "different.txt", "text/plain", strings.NewReader("different"))
	if err != nil || !reused || duplicate.ID != upload.ID {
		t.Fatalf("idempotency failed: %#v reused=%v err=%v", duplicate, reused, err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "report") || strings.Contains(entry.Name(), "..") {
			t.Fatalf("untrusted filename influenced quarantine path: %q", entry.Name())
		}
	}
}

func TestRejectedAndCancelledUploadsDoNotLeavePlaintext(t *testing.T) {
	directory := t.TempDir()
	manager, err := NewManager(Config{
		QuarantineDir: directory, MaxUploadBytes: 1024,
		InspectionTTL: time.Second, Scanner: DeterministicScanner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	upload, _, err := manager.Create(t.Context(), "usr_1", "idem-reject-1", "blocked.exe", "application/octet-stream", strings.NewReader("harmless fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if terminal := waitForTerminal(t, manager, "usr_1", upload.ID); terminal.Status != StatusRejected {
		t.Fatalf("expected rejected terminal state, got %s", terminal.Status)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected plaintext remained in quarantine: %v", entries)
	}

	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := manager.Create(cancelledContext, "usr_1", "idem-cancel-1", "cancelled.txt", "text/plain", strings.NewReader("harmless fixture")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled upload returned %v", err)
	}
	entries, err = os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cancelled upload left a quarantine object: %v", entries)
	}
}

func TestAcceptedUploadIsEncryptedStoredAndQuarantinePlaintextRemoved(t *testing.T) {
	quarantineDir := t.TempDir()
	protectedDir := t.TempDir()
	protectedRepository := protectedstore.NewMemoryRepository()
	keys, err := protectedstore.NewLocalKeyProvider(bytes.Repeat([]byte{0x52}, 32), "test-kek", "v1")
	if err != nil {
		t.Fatal(err)
	}
	protectedService, err := protectedstore.NewService(protectedstore.Config{RootDir: protectedDir, MaxPlaintextBytes: 1024, Repository: protectedRepository, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Config{QuarantineDir: quarantineDir, MaxUploadBytes: 1024, InspectionTTL: time.Second, Scanner: DeterministicScanner{}, ProtectedStore: protectedService})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("harmless content that must be encrypted")
	upload, _, err := manager.Create(t.Context(), "usr_owner", "idem-protect-1", "report.txt", "text/plain", bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	terminal := waitForTerminal(t, manager, "usr_owner", upload.ID)
	if terminal.Status != StatusStored || terminal.DecisionReason != "protected_storage_committed" {
		t.Fatalf("upload was not protected: %#v", terminal)
	}
	entries, err := os.ReadDir(quarantineDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("quarantine plaintext remained after protected commit: %v %v", entries, err)
	}
	opened, err := protectedService.Open("usr_owner", upload.ID)
	if err != nil || !bytes.Equal(opened.Bytes, plaintext) {
		t.Fatalf("stored file could not be authenticated and opened: %v", err)
	}
}

func TestAdminResourceInventoryUsesSafeRuntimeMetadata(t *testing.T) {
	manager := newTestManager(t, 1024)
	upload, _, err := manager.Create(t.Context(), "usr_owner_123", "idem-admin-1", "report.txt", "text/plain", strings.NewReader("safe runtime content"))
	if err != nil {
		t.Fatal(err)
	}
	terminal := waitForTerminal(t, manager, "usr_owner_123", upload.ID)
	if terminal.Status != StatusAccepted {
		t.Fatalf("expected accepted upload, got %s", terminal.Status)
	}

	page, err := manager.ListAdminResources("report", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Resources) != 1 {
		t.Fatalf("unexpected resource page: %#v", page)
	}
	if page.Summary.TrackedUploads != 1 || page.Summary.TrackedBytes != int64(len("safe runtime content")) || page.Summary.QuarantineBytes == 0 {
		t.Fatalf("summary did not use authoritative runtime and disk values: %#v", page.Summary)
	}
	if !page.Summary.RuntimeOnly || page.Summary.ProtectedConnected {
		t.Fatalf("runtime limitations were not represented honestly: %#v", page.Summary)
	}
	if page.Summary.BytesLast24Hours != int64(len("safe runtime content")) || page.Summary.BytesLast7Days != int64(len("safe runtime content")) || len(page.Summary.OwnerUsage) != 1 {
		t.Fatalf("capacity growth and owner usage were not aggregated: %#v", page.Summary)
	}
	if page.Summary.OwnerUsage[0].OwnerID != "usr_owner_123" || page.Summary.OwnerUsage[0].Uploads != 1 {
		t.Fatalf("unexpected owner usage: %#v", page.Summary.OwnerUsage)
	}
	resource := page.Resources[0]
	if resource.OwnerID != "usr_owner_123" || resource.Name != "report.txt" || resource.CorrelationID == "" {
		t.Fatalf("safe metadata projection was incomplete: %#v", resource)
	}
	payload, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(payload)
	if strings.Contains(serialized, "QuarantinePath") || strings.Contains(serialized, "quarantinePath") || strings.Contains(serialized, "Digest") || strings.Contains(serialized, "digest") {
		t.Fatalf("sensitive internal metadata escaped the admin projection: %s", serialized)
	}
}

func TestPendingProcessingCountUsesLifecycleState(t *testing.T) {
	manager, err := NewManager(Config{
		QuarantineDir: t.TempDir(), MaxUploadBytes: 1024, InspectionTTL: time.Second,
		TransitionDelay: 250 * time.Millisecond, Scanner: DeterministicScanner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Create(t.Context(), "usr_queue", "idem-queue-1", "queued.txt", "text/plain", strings.NewReader("queue fixture")); err != nil {
		t.Fatal(err)
	}
	page, err := manager.ListAdminResources("", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Summary.PendingProcessing != 1 || page.Summary.StatusCounts[StatusQuarantined] != 1 {
		t.Fatalf("pending processing did not reflect quarantined work: %#v", page.Summary)
	}
}

func TestEmptyAdminResourceCollectionsEncodeAsArrays(t *testing.T) {
	manager := newTestManager(t, 1024)
	page, err := manager.ListAdminResources("", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), `"ownerUsage":null`) || strings.Contains(string(payload), `"resources":null`) {
		t.Fatalf("empty API collections must encode as arrays: %s", payload)
	}
}

func TestPerOwnerQuotaIsEnforcedAcrossConcurrentUploads(t *testing.T) {
	directory := t.TempDir()
	manager, err := NewManager(Config{
		QuarantineDir: directory, MaxUploadBytes: 1024, DefaultOwnerQuotaBytes: 10,
		InspectionTTL: time.Second, TransitionDelay: 100 * time.Millisecond,
		Scanner: DeterministicScanner{},
	})
	if err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, _, createErr := manager.Create(context.Background(), "usr_quota", fmt.Sprintf("idem-quota-%d", index), fmt.Sprintf("quota-%d.txt", index), "text/plain", strings.NewReader("123456"))
			results <- createErr
		}(index)
	}
	wait.Wait()
	close(results)
	var accepted, denied int
	for result := range results {
		switch {
		case result == nil:
			accepted++
		case errors.Is(result, ErrQuotaExceeded):
			denied++
		default:
			t.Fatalf("unexpected quota result: %v", result)
		}
	}
	if accepted != 1 || denied != 1 {
		t.Fatalf("quota race was not serialized: accepted=%d denied=%d", accepted, denied)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("quota denial left partial quarantine data: %v", entries)
	}
	page, err := manager.ListAdminResources("", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Summary.QuotaAlerts != 0 || page.Summary.DefaultQuotaBytes != 10 || len(page.Summary.OwnerUsage) != 1 || page.Summary.OwnerUsage[0].QuotaBytes != 10 {
		t.Fatalf("quota summary was incorrect: %#v", page.Summary)
	}
}

func TestDurableCapacityReservationSerializesIndependentManagers(t *testing.T) {
	repository := NewMemoryRepository()
	release := make(chan struct{})
	newManager := func() *Manager {
		manager, err := NewManager(Config{
			QuarantineDir: t.TempDir(), MaxUploadBytes: 20, DefaultOwnerQuotaBytes: 100,
			StorageCapacityBytes: 20, StorageReserveBytes: 10, ReservationTTL: time.Hour,
			InspectionTTL: time.Minute, Scanner: gatedScanner{release: release}, Repository: repository,
		})
		if err != nil {
			t.Fatal(err)
		}
		return manager
	}
	first, second := newManager(), newManager()
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for index, manager := range []*Manager{first, second} {
		wait.Add(1)
		go func(index int, manager *Manager) {
			defer wait.Done()
			_, _, err := manager.CreateSized(t.Context(), "usr_pool", fmt.Sprintf("capacity-%d", index), "capacity.bin", "application/octet-stream", strings.NewReader("123456"), 6)
			results <- err
		}(index, manager)
	}
	wait.Wait()
	close(results)
	defer close(release)
	var accepted, denied int
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrCapacityExceeded) {
			denied++
		} else {
			t.Fatalf("unexpected capacity result: %v", err)
		}
	}
	if accepted != 1 || denied != 1 {
		t.Fatalf("global capacity was oversubscribed: accepted=%d denied=%d", accepted, denied)
	}
	summary, err := repository.CapacityReservationSummary(time.Now().UTC())
	if err != nil || summary.Active != 1 || summary.Bytes != 6 {
		t.Fatalf("active reservation signal was inaccurate: %#v %v", summary, err)
	}
}

func TestSizedUploadRejectsByteMismatchAndReleasesReservation(t *testing.T) {
	repository := NewMemoryRepository()
	manager, err := NewManager(Config{
		QuarantineDir: t.TempDir(), MaxUploadBytes: 20, DefaultOwnerQuotaBytes: 100,
		StorageCapacityBytes: 100, StorageReserveBytes: 10, ReservationTTL: time.Hour,
		InspectionTTL: time.Second, Scanner: DeterministicScanner{}, Repository: repository,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.CreateSized(t.Context(), "usr_size", "size-mismatch", "short.bin", "application/octet-stream", strings.NewReader("short"), 6); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("short body was accepted: %v", err)
	}
	summary, err := repository.CapacityReservationSummary(time.Now().UTC())
	if err != nil || summary.Active != 0 || len(repository.records) != 0 {
		t.Fatalf("failed reception leaked capacity or metadata: %#v records=%d err=%v", summary, len(repository.records), err)
	}
}

func TestQuotaThresholdAlertAtEightyPercent(t *testing.T) {
	manager, err := NewManager(Config{QuarantineDir: t.TempDir(), MaxUploadBytes: 1024, DefaultOwnerQuotaBytes: 10, InspectionTTL: time.Second, Scanner: DeterministicScanner{}})
	if err != nil {
		t.Fatal(err)
	}
	upload, _, err := manager.Create(t.Context(), "usr_alert", "idem-alert-1", "alert.txt", "text/plain", strings.NewReader("12345678"))
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForTerminal(t, manager, "usr_alert", upload.ID)
	page, err := manager.ListAdminResources("", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Summary.QuotaAlerts != 1 {
		t.Fatalf("80 percent quota threshold was not reported: %#v", page.Summary)
	}
}

func TestOwnerQuotaOverridePersistsAndControlsUploads(t *testing.T) {
	directory := t.TempDir()
	repository := NewMemoryRepository()
	config := Config{
		QuarantineDir: directory, MaxUploadBytes: 2 * 1024 * 1024,
		DefaultOwnerQuotaBytes: 2 * 1024 * 1024, InspectionTTL: time.Second,
		Scanner: DeterministicScanner{}, Repository: repository,
	}
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetOwnerQuota("usr_override", 1024*1024); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	page, err := reloaded.ListAdminResources("", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Summary.QuotaOverrides) != 1 || page.Summary.QuotaOverrides[0].QuotaBytes != 1024*1024 {
		t.Fatalf("quota override did not survive manager recreation: %#v", page.Summary.QuotaOverrides)
	}
	_, _, err = reloaded.Create(t.Context(), "usr_override", "idem-override-1", "over-quota.bin", "application/octet-stream", bytes.NewReader(make([]byte, 1024*1024+1)))
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("owner override was not enforced: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("override denial left quarantine data: %v", entries)
	}
	if _, err := reloaded.ResetOwnerQuotaAudited("usr_override", auditoutbox.Intent{}); err != nil {
		t.Fatal(err)
	}
	restored, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	restoredPage, err := restored.ListAdminResources("", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(restoredPage.Summary.QuotaOverrides) != 0 {
		t.Fatalf("organization default restoration retained an override: %#v", restoredPage.Summary.QuotaOverrides)
	}
	if _, _, err := restored.Create(t.Context(), "usr_override", "idem-default-1", "default-quota.bin", "application/octet-stream", bytes.NewReader(make([]byte, 1024*1024+1))); err != nil {
		t.Fatalf("restored organization default did not admit an in-policy upload: %v", err)
	}
}

func TestMetadataReloadAndOrphanReconciliation(t *testing.T) {
	directory := t.TempDir()
	repository := NewMemoryRepository()
	config := Config{
		QuarantineDir: directory, MaxUploadBytes: 1024, InspectionTTL: time.Second,
		Scanner: DeterministicScanner{}, Repository: repository,
	}
	first, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	upload, _, err := first.Create(t.Context(), "usr_restart", "idem-restart-1", "restart.txt", "text/plain", strings.NewReader("durable fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if terminal := waitForTerminal(t, first, "usr_restart", upload.ID); terminal.Status != StatusAccepted {
		t.Fatalf("unexpected terminal state: %s", terminal.Status)
	}

	reloaded, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := reloaded.Get("usr_restart", upload.ID)
	if err != nil || restored.Status != StatusAccepted {
		t.Fatalf("metadata did not survive manager recreation: %#v err=%v", restored, err)
	}
	reused, duplicate, err := reloaded.Create(t.Context(), "usr_restart", "idem-restart-1", "different.txt", "text/plain", strings.NewReader("different"))
	if err != nil || !duplicate || reused.ID != upload.ID {
		t.Fatalf("durable idempotency was not preserved: %#v duplicate=%v err=%v", reused, duplicate, err)
	}

	orphanPath := directory + string(os.PathSeparator) + "unmatched.upload"
	if err := os.WriteFile(orphanPath, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	page, err := reloaded.ListAdminResources("", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Summary.OrphanedObjects != 1 || page.Summary.OrphanedBytes != int64(len("orphan")) {
		t.Fatalf("orphaned quarantine object was not reported: %#v", page.Summary)
	}
}

func TestMissingQuarantineObjectFailsClosedOnReload(t *testing.T) {
	directory := t.TempDir()
	repository := NewMemoryRepository()
	record := persistedRecord{
		Upload:  Upload{ID: "upl_missing", Name: "missing.txt", Status: StatusAccepted, Progress: 100, CreatedAt: time.Now().UTC()},
		OwnerID: "usr_missing", QuarantineObject: "upl_missing.upload",
		IdempotencyHash: strings.Repeat("a", 64),
	}
	if _, _, err := repository.Create(record); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Config{QuarantineDir: directory, MaxUploadBytes: 1024, InspectionTTL: time.Second, Scanner: DeterministicScanner{}, Repository: repository})
	if err != nil {
		t.Fatal(err)
	}
	upload, err := manager.Get("usr_missing", "upl_missing")
	if err != nil {
		t.Fatal(err)
	}
	if upload.Status != StatusFailed || upload.DecisionReason != "quarantine_object_missing" {
		t.Fatalf("missing quarantine object was not failed closed: %#v", upload)
	}
}

func newTestManager(t *testing.T, maxBytes int64) *Manager {
	t.Helper()
	manager, err := NewManager(Config{
		QuarantineDir: t.TempDir(), MaxUploadBytes: maxBytes,
		InspectionTTL: time.Second, Scanner: DeterministicScanner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func waitForTerminal(t *testing.T, manager *Manager, ownerID, uploadID string) Upload {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		upload, err := manager.Get(ownerID, uploadID)
		if err != nil {
			t.Fatal(err)
		}
		if upload.Status == StatusAccepted || upload.Status == StatusStored || upload.Status == StatusRejected || upload.Status == StatusFailed {
			return upload
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("inspection did not reach a terminal state")
	return Upload{}
}
