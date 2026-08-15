package authn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"securestore/internal/auditoutbox"
)

func TestPostgresAccountStatusAndAuditIntentAreAtomic(t *testing.T) {
	databaseURL := os.Getenv("SECURESTORE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SECURESTORE_TEST_DATABASE_URL is not set")
	}
	repository, err := NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	suffix := time.Now().UnixNano()
	userID, email := fmt.Sprintf("usr_atomic_%d", suffix), fmt.Sprintf("atomic-%d@example.edu", suffix)
	_, err = repository.pool.Exec(context.Background(), `INSERT INTO securestore_users(id,name,email,password_hash,role,email_verified_at,created_at,account_status) VALUES($1,'Atomic Test',$2,$3,'user',now(),now(),'active')`, userID, email, []byte("test-only-hash"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_audit_outbox WHERE resource_id=$1`, userID)
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_users WHERE id=$1`, userID)
	}()

	invalid := auditoutbox.Intent{EventID: "evt_invalid", OccurredAt: time.Now().UTC(), ActorType: "user", Action: "", ResourceType: "user", ResourceID: userID, Outcome: "success"}
	if err := repository.UpdateUserStatusAndDeleteSessionsAudited(userID, "suspended", invalid); err == nil {
		t.Fatal("invalid audit intent unexpectedly committed")
	}
	var status string
	if err := repository.pool.QueryRow(context.Background(), `SELECT account_status FROM securestore_users WHERE id=$1`, userID).Scan(&status); err != nil || status != "active" {
		t.Fatalf("mutation was not rolled back with audit failure: status=%s err=%v", status, err)
	}

	intent := auditoutbox.Intent{EventID: fmt.Sprintf("evt_atomic_%d", suffix), OccurredAt: time.Now().UTC().Truncate(time.Microsecond), ActorType: "user", ActorID: "admin_test", Action: "ACCOUNT_STATUS_UPDATED", ResourceType: "user", ResourceID: userID, Outcome: "success", ReasonCode: "administrator_action", ToState: "suspended"}
	if err := repository.UpdateUserStatusAndDeleteSessionsAudited(userID, "suspended", intent); err != nil {
		t.Fatal(err)
	}
	var outboxCount int
	if err := repository.pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_audit_outbox WHERE event_id=$1 AND resource_id=$2`, intent.EventID, userID).Scan(&outboxCount); err != nil || outboxCount != 1 {
		t.Fatalf("mutation evidence was not atomically persisted: count=%d err=%v", outboxCount, err)
	}
	if err := repository.pool.QueryRow(context.Background(), `SELECT account_status FROM securestore_users WHERE id=$1`, userID).Scan(&status); err != nil || status != "suspended" {
		t.Fatalf("audited mutation did not commit: status=%s err=%v", status, err)
	}
}

func TestPostgresPrivilegedActivationAndAuditIntentAreAtomic(t *testing.T) {
	databaseURL := os.Getenv("SECURESTORE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SECURESTORE_TEST_DATABASE_URL is not set")
	}
	repository, err := NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	suffix := time.Now().UnixNano()
	tokenHash := sha256.Sum256([]byte(fmt.Sprintf("activation-%d", suffix)))
	userID := fmt.Sprintf("usr_activation_%d", suffix)
	inviterID := fmt.Sprintf("usr_inviter_%d", suffix)
	email := fmt.Sprintf("activation-%d@example.edu", suffix)
	eventID := fmt.Sprintf("evt_activation_%d", suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = repository.pool.Exec(context.Background(), `INSERT INTO securestore_users(id,name,email,password_hash,role,email_verified_at,created_at,account_status) VALUES($1,'Inviter Test',$2,$3,'admin',now(),now(),'active')`, inviterID, fmt.Sprintf("inviter-%d@example.edu", suffix), []byte("test-only-hash"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_audit_outbox WHERE event_id=$1`, eventID)
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_users WHERE id=$1`, userID)
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_privileged_invitations WHERE token_hash=$1`, tokenHash[:])
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_users WHERE id=$1`, inviterID)
	}()
	invitation := PrivilegedInvitation{InvitedBy: inviterID, Name: "Activation Test", Email: email, Role: "auditor", ExpiresAt: now.Add(time.Hour)}
	if err := repository.CreatePrivilegedInvitation(tokenHash, invitation, now); err != nil {
		t.Fatal(err)
	}
	record := UserRecord{User: User{ID: userID}, PasswordHash: []byte("test-only-hash"), CreatedAt: now, AccountStatus: "active"}
	invalid := auditoutbox.Intent{EventID: "evt_invalid", OccurredAt: now, ActorType: "user", Action: "", ResourceType: "identity", Outcome: "success"}
	if _, err := repository.AcceptPrivilegedInvitationAudited(tokenHash, record, now, invalid); err == nil {
		t.Fatal("invalid activation evidence unexpectedly committed")
	}
	var acceptedAt *time.Time
	if err := repository.pool.QueryRow(context.Background(), `SELECT accepted_at FROM securestore_privileged_invitations WHERE token_hash=$1`, tokenHash[:]).Scan(&acceptedAt); err != nil || acceptedAt != nil {
		t.Fatalf("invitation consumption was not rolled back: accepted=%v err=%v", acceptedAt, err)
	}
	intent := auditoutbox.Intent{EventID: eventID, OccurredAt: now, ActorType: "user", Action: "PRIVILEGED_ACCOUNT_ACTIVATED", ResourceType: "identity", Outcome: "success", ReasonCode: "invitation_accepted"}
	created, err := repository.AcceptPrivilegedInvitationAudited(tokenHash, record, now, intent)
	if err != nil || created.ID != userID || created.Role != "auditor" {
		t.Fatalf("audited activation failed: user=%#v err=%v", created, err)
	}
	var evidence int
	if err := repository.pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_audit_outbox WHERE event_id=$1 AND actor_id=$2 AND to_state='auditor'`, eventID, userID).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatalf("activation evidence missing: count=%d err=%v", evidence, err)
	}
}

func TestPostgresVerificationAndSessionPersistence(t *testing.T) {
	databaseURL := os.Getenv("SECURESTORE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SECURESTORE_TEST_DATABASE_URL is not set")
	}

	repository, err := NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	email := fmt.Sprintf("postgres-flow-%d@example.edu", time.Now().UnixNano())
	defer func() {
		_, _ = repository.pool.Exec(context.Background(), `DELETE FROM securestore_users WHERE email = $1`, email)
	}()

	mailer := &captureMailer{}
	store, err := NewStoreWithConfig(Config{
		Repository: repository, Mailer: mailer, SessionTTL: time.Hour,
		VerificationTTL: 30 * time.Minute, VerificationMinResend: time.Minute,
		PublicAppURL: "http://test.local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register("Postgres Test", email, "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Login(email, "Correct-Horse-9!"); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("unverified PostgreSQL account was not blocked: %v", err)
	}

	token := mailer.lastToken(t)
	hash := sha256.Sum256([]byte(token))
	var storedLength int
	if err := repository.pool.QueryRow(context.Background(), `SELECT octet_length(token_hash) FROM securestore_email_verification_tokens WHERE token_hash = $1`, hash[:]).Scan(&storedLength); err != nil {
		t.Fatal(err)
	}
	if storedLength != sha256.Size {
		t.Fatalf("verification token was not stored as a SHA-256 digest: %d", storedLength)
	}
	if err := store.VerifyEmail(token); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEmail(token); !errors.Is(err, ErrVerificationToken) {
		t.Fatalf("PostgreSQL token was reusable: %v", err)
	}

	_, sessionToken, _, err := store.Login(email, "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	reloadedStore, err := NewStoreWithConfig(Config{
		Repository: repository, Mailer: DiscardMailer{}, SessionTTL: time.Hour,
		PublicAppURL: "http://test.local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloadedStore.Authenticate(sessionToken); err != nil {
		t.Fatalf("session did not survive service recreation: %v", err)
	}
}
