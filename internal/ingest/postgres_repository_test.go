package ingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"securestore/internal/auditoutbox"
	"securestore/internal/authn"
)

func TestPostgresCapacityReservationPreventsCrossProcessOversubscription(t *testing.T) {
	databaseURL := os.Getenv("SECURESTORE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SECURESTORE_TEST_DATABASE_URL is not set")
	}
	authRepository, err := authn.NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer authRepository.Close()
	repository, err := NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()

	suffix := time.Now().UnixNano()
	ownerID := fmt.Sprintf("usr_capacity_%d", suffix)
	_, err = repository.pool.Exec(context.Background(), `INSERT INTO securestore_users(id,name,email,password_hash,role,email_verified_at,created_at,account_status) VALUES($1,'Capacity Test',$2,$3,'user',now(),now(),'active')`, ownerID, fmt.Sprintf("capacity-%d@example.edu", suffix), []byte("test-only-hash"))
	if err != nil {
		t.Fatal(err)
	}
	uploadIDs := []string{fmt.Sprintf("upl_capacity_a_%d", suffix), fmt.Sprintf("upl_capacity_b_%d", suffix)}
	defer func() {
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_uploads WHERE owner_id=$1`, ownerID)
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_users WHERE id=$1`, ownerID)
	}()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for index, uploadID := range uploadIDs {
		record := persistedRecord{Upload: Upload{ID: uploadID, Name: "capacity.bin", Status: StatusQuarantined, Progress: 5, CorrelationID: fmt.Sprintf("corr_%d", index), CreatedAt: now}, OwnerID: ownerID, QuarantineObject: uploadID + ".upload", IdempotencyHash: fmt.Sprintf("%064x", suffix+int64(index))}
		if _, _, err := repository.Create(record); err != nil {
			t.Fatal(err)
		}
	}
	var baselineBytes int64
	if err := repository.pool.QueryRow(context.Background(), `SELECT COALESCE((SELECT sum(u.size_bytes) FROM securestore_uploads u WHERE u.status IN ('quarantined','inspecting','accepted','encrypting','stored') AND NOT EXISTS(SELECT 1 FROM securestore_capacity_reservations r WHERE r.upload_id=u.id AND r.expires_at>$1)),0)+COALESCE((SELECT sum(reserved_bytes) FROM securestore_capacity_reservations WHERE expires_at>$1),0)`, now).Scan(&baselineBytes); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, uploadID := range uploadIDs {
		wait.Add(1)
		go func(uploadID string) {
			defer wait.Done()
			results <- repository.ReserveCapacity(CapacityReservationRequest{UploadID: uploadID, OwnerID: ownerID, Bytes: 6, OwnerQuotaBytes: 100, StorageCapacityBytes: baselineBytes + 20, StorageReserveBytes: 10, Now: now, ExpiresAt: now.Add(time.Hour)})
		}(uploadID)
	}
	wait.Wait()
	close(results)
	var accepted, denied int
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrCapacityExceeded) {
			denied++
		} else {
			t.Fatalf("unexpected reservation error: %v", err)
		}
	}
	if accepted != 1 || denied != 1 {
		t.Fatalf("database capacity was oversubscribed: accepted=%d denied=%d", accepted, denied)
	}
	summary, err := repository.CapacityReservationSummary(now)
	if err != nil || summary.Active < 1 {
		t.Fatalf("durable reservation was not observable: %#v %v", summary, err)
	}
}

func TestPostgresLifecycleTransitionAndAuditIntentAreAtomic(t *testing.T) {
	databaseURL := os.Getenv("SECURESTORE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SECURESTORE_TEST_DATABASE_URL is not set")
	}
	authRepository, err := authn.NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer authRepository.Close()
	repository, err := NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	suffix := time.Now().UnixNano()
	userID, uploadID := fmt.Sprintf("usr_transition_%d", suffix), fmt.Sprintf("upl_transition_%d", suffix)
	_, err = repository.pool.Exec(context.Background(), `INSERT INTO securestore_users(id,name,email,password_hash,role,email_verified_at,created_at,account_status) VALUES($1,'Transition Test',$2,$3,'user',now(),now(),'active')`, userID, fmt.Sprintf("transition-%d@example.edu", suffix), []byte("test-only-hash"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_audit_outbox WHERE resource_id=$1`, uploadID)
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_uploads WHERE id=$1`, uploadID)
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_users WHERE id=$1`, userID)
	}()
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := persistedRecord{Upload: Upload{ID: uploadID, Name: "fixture.txt", Size: 1, DeclaredMediaType: "text/plain", DetectedMediaType: "text/plain", Status: StatusQuarantined, Progress: 25, CorrelationID: "corr_transition", CreatedAt: now}, OwnerID: userID, QuarantineObject: uploadID + ".upload", Digest: fmt.Sprintf("%064x", suffix), IdempotencyHash: fmt.Sprintf("%064x", suffix+1)}
	if _, _, err := repository.Create(record); err != nil {
		t.Fatal(err)
	}
	record.Status, record.Progress = StatusInspecting, 60
	invalid := auditoutbox.Intent{EventID: "evt_invalid", OccurredAt: now, ActorType: "system", Action: "", ResourceType: "upload", ResourceID: uploadID, Outcome: "success"}
	if err := repository.UpdateAudited(record, invalid); err == nil {
		t.Fatal("invalid transition evidence unexpectedly committed")
	}
	var status Status
	if err := repository.pool.QueryRow(context.Background(), `SELECT status FROM securestore_uploads WHERE id=$1`, uploadID).Scan(&status); err != nil || status != StatusQuarantined {
		t.Fatalf("transition was not rolled back: status=%s err=%v", status, err)
	}
	intent := auditoutbox.Intent{EventID: fmt.Sprintf("evt_transition_%d", suffix), OccurredAt: now, ActorType: "system", ActorID: userID, Action: "FILE_INSPECTION_STARTED", ResourceType: "upload", ResourceID: uploadID, Outcome: "success", ReasonCode: "content_policy_evaluation", CorrelationID: "corr_transition", FromState: string(StatusQuarantined), ToState: string(StatusInspecting)}
	if err := repository.UpdateAudited(record, intent); err != nil {
		t.Fatal(err)
	}
	var evidence int
	if err := repository.pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_audit_outbox WHERE event_id=$1`, intent.EventID).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatalf("transition evidence missing: count=%d err=%v", evidence, err)
	}
}

func TestPostgresMetadataSurvivesManagerRecreation(t *testing.T) {
	databaseURL := os.Getenv("SECURESTORE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SECURESTORE_TEST_DATABASE_URL is not set")
	}

	// The authentication migration owns the user table referenced by upload
	// metadata. Production initializes repositories in this same order.
	authRepository, err := authn.NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer authRepository.Close()
	repository, err := NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()

	suffix := time.Now().UnixNano()
	userID := fmt.Sprintf("usr_ingest_%d", suffix)
	email := fmt.Sprintf("ingest-%d@example.edu", suffix)
	_, err = repository.pool.Exec(context.Background(), `
		INSERT INTO securestore_users
			(id, name, email, password_hash, role, email_verified_at, created_at, account_status)
		VALUES ($1, 'Ingest Test', $2, $3, 'user', now(), now(), 'active')`, userID, email, []byte("test-only-password-hash"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_uploads WHERE owner_id = $1`, userID)
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_users WHERE id = $1`, userID)
	}()

	directory := t.TempDir()
	config := Config{
		QuarantineDir: directory, MaxUploadBytes: 1024, InspectionTTL: time.Second,
		Scanner: DeterministicScanner{}, Repository: repository,
	}
	first, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	upload, _, err := first.Create(t.Context(), userID, "idem-postgres-restart", "postgres.txt", "text/plain", strings.NewReader("postgres fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if terminal := waitForTerminal(t, first, userID, upload.ID); terminal.Status != StatusAccepted {
		t.Fatalf("unexpected terminal status: %s", terminal.Status)
	}

	reloaded, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := reloaded.Get(userID, upload.ID)
	if err != nil || restored.Status != StatusAccepted {
		t.Fatalf("PostgreSQL metadata did not survive manager recreation: %#v err=%v", restored, err)
	}
	page, err := reloaded.ListAdminResources("postgres.txt", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || !page.Summary.MetadataDurable || page.Summary.RuntimeOnly {
		t.Fatalf("durable repository status was not exposed: %#v", page)
	}
	if err := reloaded.SetOwnerQuota(userID, 64*1024*1024); err != nil {
		t.Fatal(err)
	}
	third, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	quotaPage, err := third.ListAdminResources("", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(quotaPage.Summary.QuotaOverrides) != 1 || quotaPage.Summary.QuotaOverrides[0].OwnerID != userID || quotaPage.Summary.QuotaOverrides[0].QuotaBytes != 64*1024*1024 {
		t.Fatalf("PostgreSQL quota override was not durable: %#v", quotaPage.Summary.QuotaOverrides)
	}
	if _, err := third.ResetOwnerQuotaAudited(userID, auditoutbox.Intent{}); err != nil {
		t.Fatal(err)
	}
	fourth, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	defaultPage, err := fourth.ListAdminResources("", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultPage.Summary.QuotaOverrides) != 0 {
		t.Fatalf("PostgreSQL quota reset was not durable: %#v", defaultPage.Summary.QuotaOverrides)
	}
}
