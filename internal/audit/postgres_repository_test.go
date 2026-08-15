package audit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestPostgresAuditPersistsAcrossReconnect is intentionally opt-in because it
// requires a real PostgreSQL instance. It appends a harmless test event to the
// immutable chain, then recreates the repository to prove that both the event
// and the HMAC verification checkpoint survive a process boundary.
func TestPostgresAuditPersistsAcrossReconnect(t *testing.T) {
	databaseURL := os.Getenv("SECURESTORE_TEST_DATABASE_URL")
	encodedKey := os.Getenv("SECURESTORE_TEST_AUDIT_HMAC_KEY")
	if databaseURL == "" || encodedKey == "" {
		t.Skip("set SECURESTORE_TEST_DATABASE_URL and SECURESTORE_TEST_AUDIT_HMAC_KEY to run the PostgreSQL integration test")
	}
	key, err := DecodeKey(encodedKey)
	if err != nil {
		t.Fatalf("decode audit test key: %v", err)
	}

	repository, err := NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("open PostgreSQL audit repository: %v", err)
	}
	service, err := NewService(repository, key)
	if err != nil {
		repository.Close()
		t.Fatalf("create audit service: %v", err)
	}
	marker := fmt.Sprintf("integration-%d", time.Now().UTC().UnixNano())
	appended, err := service.Append(Input{
		ActorType:     "system",
		ActorID:       "integration-test",
		Action:        "AUDIT_PERSISTENCE_TEST",
		ResourceType:  "audit_chain",
		ResourceID:    marker,
		Outcome:       "success",
		ReasonCode:    "automated_verification",
		CorrelationID: marker,
	})
	if err != nil {
		repository.Close()
		t.Fatalf("append audit event: %v", err)
	}
	repository.Close()

	reopened, err := NewPostgresRepository(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("reopen PostgreSQL audit repository: %v", err)
	}
	defer reopened.Close()
	reconnected, err := NewService(reopened, key)
	if err != nil {
		t.Fatalf("create reconnected audit service: %v", err)
	}
	page, err := reconnected.List(Query{Search: marker, Limit: 10})
	if err != nil {
		t.Fatalf("list persisted audit event: %v", err)
	}
	if page.Total != 1 || len(page.Events) != 1 || page.Events[0].EventID != appended.EventID {
		t.Fatalf("persisted event mismatch: total=%d events=%d", page.Total, len(page.Events))
	}
	if !page.Verification.Valid || page.Verification.VerifiedThrough < appended.Sequence {
		t.Fatalf("reconnected chain verification failed: %+v", page.Verification)
	}
}
