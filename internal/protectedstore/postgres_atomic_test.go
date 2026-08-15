package protectedstore_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"securestore/internal/auditoutbox"
	"securestore/internal/authn"
	"securestore/internal/ingest"
	"securestore/internal/protectedstore"
)

// This integration test proves the protected-file transaction itself owns the
// audit durability boundary. An invalid intent must roll back the policy change
// rather than leaving a successful retention mutation without evidence.
func TestPostgresRetentionAndAuditIntentAreAtomic(t *testing.T) {
	databaseURL := os.Getenv("SECURESTORE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SECURESTORE_TEST_DATABASE_URL is not set")
	}
	authRepository, err := authn.NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer authRepository.Close()
	ingestRepository, err := ingest.NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer ingestRepository.Close()
	repository, err := protectedstore.NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	suffix := time.Now().UnixNano()
	ownerID := fmt.Sprintf("usr_protected_atomic_%d", suffix)
	uploadID := fmt.Sprintf("upl_protected_atomic_%d", suffix)
	versionID := fmt.Sprintf("ver_protected_atomic_%d", suffix)
	fileID := fmt.Sprintf("file_protected_atomic_%d", suffix)
	eventID := fmt.Sprintf("evt_protected_atomic_%d", suffix)
	drillEventID := fmt.Sprintf("evt_recovery_atomic_%d", suffix)
	drillID := fmt.Sprintf("drill_atomic_%d", suffix)
	_, err = pool.Exec(context.Background(), `INSERT INTO securestore_users(id,name,email,password_hash,role,email_verified_at,created_at,account_status) VALUES($1,'Protected Atomic',$2,$3,'user',now(),now(),'active')`, ownerID, fmt.Sprintf("protected-atomic-%d@example.edu", suffix), []byte("test-only-hash"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM securestore_audit_outbox WHERE event_id IN ($1,$2)`, eventID, drillEventID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM securestore_recovery_drills WHERE drill_id=$1`, drillID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM securestore_file_versions WHERE file_id=$1`, fileID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM securestore_files WHERE file_id=$1`, fileID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM securestore_protected_versions WHERE version_id=$1`, versionID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM securestore_uploads WHERE id=$1`, uploadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM securestore_users WHERE id=$1`, ownerID)
	}()
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = pool.Exec(context.Background(), `INSERT INTO securestore_uploads(id,owner_id,idempotency_hash,name,size_bytes,declared_media_type,detected_media_type,status,progress,decision_reason,correlation_id,quarantine_object,content_digest,created_at,updated_at) VALUES($1,$2,$3,'fixture.txt',1,'text/plain','text/plain','stored',100,'protected','corr_fixture','fixture.quarantine',$4,$5,$5)`, uploadID, ownerID, make([]byte, 32), fmt.Sprintf("%064x", suffix), now)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture represents an envelope that has not yet been rewrapped, so
	// its immutable origin and current wrapping-key identities are the same.
	_, err = pool.Exec(context.Background(), `INSERT INTO securestore_protected_versions(version_id,operation_id,owner_id,blob_object,schema_version,algorithm,kek_id,kek_version,wrapping_kek_id,wrapping_kek_version,wrapped_dek,nonce,plaintext_size,plaintext_digest,media_type,inspection_record_id,created_at) VALUES($1,$2,$3,$4,'securestore-envelope-v1','AES-256-GCM','test','v1','test','v1',$5,$6,1,$7,'text/plain','inspect_fixture',$8)`, versionID, uploadID, ownerID, versionID+".ciphertext", []byte{1}, make([]byte, 12), fmt.Sprintf("%064x", suffix), now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(context.Background(), `INSERT INTO securestore_files(file_id,owner_id,name,current_version_id,created_at,updated_at) VALUES($1,$2,'fixture.txt',$3,$4,$4)`, fileID, ownerID, versionID, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(context.Background(), `INSERT INTO securestore_file_versions(file_id,version_id,operation_id,version_number,plaintext_size,media_type,reason,created_at) VALUES($1,$2,$3,1,1,'text/plain','initial_upload',$4)`, fileID, versionID, uploadID, now)
	if err != nil {
		t.Fatal(err)
	}

	until := now.Add(24 * time.Hour)
	invalid := auditoutbox.Intent{EventID: "evt_invalid", OccurredAt: now, ActorType: "user", Action: "", ResourceType: "file", ResourceID: fileID, Outcome: "success"}
	if _, err := repository.SetRetentionAudited(fileID, &until, invalid); err == nil {
		t.Fatal("invalid audit intent unexpectedly committed")
	}
	var storedUntil *time.Time
	if err := pool.QueryRow(context.Background(), `SELECT retention_until FROM securestore_files WHERE file_id=$1`, fileID).Scan(&storedUntil); err != nil || storedUntil != nil {
		t.Fatalf("retention mutation was not rolled back: until=%v err=%v", storedUntil, err)
	}

	intent := auditoutbox.Intent{EventID: eventID, OccurredAt: now, ActorType: "user", ActorID: "admin_test", Action: "FILE_RETENTION_UPDATED", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "administrator_policy", ToState: until.Format(time.RFC3339)}
	if _, err := repository.SetRetentionAudited(fileID, &until, intent); err != nil {
		t.Fatal(err)
	}
	var evidence int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_audit_outbox WHERE event_id=$1 AND resource_id=$2`, eventID, fileID).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatalf("retention evidence was not committed atomically: count=%d err=%v", evidence, err)
	}
	drill := protectedstore.RecoveryDrill{DrillID: drillID, FileID: fileID, VersionID: versionID, RequestedBy: ownerID, Outcome: "verified", ReasonCode: "envelope_ciphertext_and_digest_verified", VerifiedAt: now}
	if err := repository.RecordRecoveryDrillAudited(drill, invalid); err == nil {
		t.Fatal("invalid recovery evidence unexpectedly committed")
	}
	var drills int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_recovery_drills WHERE drill_id=$1`, drillID).Scan(&drills); err != nil || drills != 0 {
		t.Fatalf("recovery evidence did not roll back: count=%d err=%v", drills, err)
	}
	drillIntent := auditoutbox.Intent{EventID: drillEventID, OccurredAt: now, ActorType: "user", ActorID: ownerID, Action: "RECOVERY_DRILL_COMPLETED", ResourceType: "file", ResourceID: fileID, Outcome: "verified", ReasonCode: drill.ReasonCode, ToState: "verified"}
	if err := repository.RecordRecoveryDrillAudited(drill, drillIntent); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_audit_outbox WHERE event_id=$1`, drillEventID).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatalf("recovery audit evidence missing: count=%d err=%v", evidence, err)
	}
}

func TestPostgresOrphanJournalAndAuditIntentAreAtomic(t *testing.T) {
	databaseURL := os.Getenv("SECURESTORE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SECURESTORE_TEST_DATABASE_URL is not set")
	}
	repository, err := protectedstore.NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	suffix := time.Now().UnixNano()
	now := time.Now().UTC().Truncate(time.Microsecond)
	operation := protectedstore.OrphanReconciliationOperation{
		OperationID: fmt.Sprintf("reconcile_atomic_%d", suffix), Token: fmt.Sprintf("orp_atomic_%d", suffix),
		Zone: "quarantine", StorageObject: fmt.Sprintf("object-%d.upload", suffix), Size: 12,
		ModifiedAt: now.Add(-2 * time.Hour), ActorID: "admin_atomic", CorrelationID: "corr_atomic",
		Status: protectedstore.ReconciliationAuthorized, ReasonCode: "administrator_reconciliation", AuthorizedAt: now,
	}
	authorizationEventID := fmt.Sprintf("evt_reconcile_authorize_%d", suffix)
	completionEventID := fmt.Sprintf("evt_reconcile_complete_%d", suffix)
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM securestore_audit_outbox WHERE event_id IN ($1,$2)`, authorizationEventID, completionEventID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM securestore_orphan_reconciliation_operations WHERE operation_id=$1`, operation.OperationID)
	}()
	invalid := auditoutbox.Intent{EventID: "invalid", OccurredAt: now, ActorType: "user", Action: "", ResourceType: "storage_orphan", Outcome: "success"}
	if _, _, err := repository.AuthorizeOrphanReconciliation(operation, invalid); err == nil {
		t.Fatal("invalid authorization evidence unexpectedly committed")
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_orphan_reconciliation_operations WHERE operation_id=$1`, operation.OperationID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("authorization journal did not roll back: count=%d err=%v", count, err)
	}
	authorizationIntent := auditoutbox.Intent{EventID: authorizationEventID, OccurredAt: now, ActorType: "user", ActorID: operation.ActorID, Action: "ORPHAN_DELETION_AUTHORIZED", ResourceType: "storage_orphan", ResourceID: operation.Token, Outcome: "success", ReasonCode: operation.ReasonCode}
	if _, created, err := repository.AuthorizeOrphanReconciliation(operation, authorizationIntent); err != nil || !created {
		t.Fatalf("valid authorization was not committed: created=%v err=%v", created, err)
	}
	if updated, err := repository.CompleteOrphanReconciliation(operation.OperationID, protectedstore.ReconciliationCompleted, "untracked_object_removed", now, invalid); err == nil || updated {
		t.Fatal("invalid completion evidence unexpectedly committed")
	}
	var status string
	if err := pool.QueryRow(context.Background(), `SELECT status FROM securestore_orphan_reconciliation_operations WHERE operation_id=$1`, operation.OperationID).Scan(&status); err != nil || status != protectedstore.ReconciliationAuthorized {
		t.Fatalf("completion journal did not roll back: status=%s err=%v", status, err)
	}
	completionIntent := auditoutbox.Intent{EventID: completionEventID, OccurredAt: now, ActorType: "system", ActorID: "reconciliation-worker", Action: "ORPHAN_DELETION_COMPLETED", ResourceType: "storage_orphan", ResourceID: operation.Token, Outcome: "success", ReasonCode: "untracked_object_removed"}
	if updated, err := repository.CompleteOrphanReconciliation(operation.OperationID, protectedstore.ReconciliationCompleted, "untracked_object_removed", now, completionIntent); err != nil || !updated {
		t.Fatalf("valid completion was not committed: updated=%v err=%v", updated, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_audit_outbox WHERE event_id IN ($1,$2)`, authorizationEventID, completionEventID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("journal evidence was not committed atomically: count=%d err=%v", count, err)
	}
}
