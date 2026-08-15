package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"securestore/internal/auditoutbox"
)

type outboxTestRepository struct {
	base       *MemoryRepository
	pending    []auditoutbox.Intent
	failAppend bool
}

func (r *outboxTestRepository) Durable() bool { return true }
func (r *outboxTestRepository) Append(event Event, compute func(int64, []byte, Event) []byte) (Event, error) {
	if r.failAppend {
		return Event{}, errors.New("injected chain failure")
	}
	return r.base.Append(event, compute)
}
func (r *outboxTestRepository) LoadChain() ([]Event, Checkpoint, error) { return r.base.LoadChain() }
func (r *outboxTestRepository) List(query Query) ([]Event, int, error)  { return r.base.List(query) }
func (r *outboxTestRepository) Summary(query Query, now time.Time) (Summary, error) {
	return r.base.Summary(query, now)
}
func (r *outboxTestRepository) PendingOutbox(limit int) ([]auditoutbox.Intent, error) {
	if limit > len(r.pending) {
		limit = len(r.pending)
	}
	return append([]auditoutbox.Intent(nil), r.pending[:limit]...), nil
}
func (r *outboxTestRepository) MarkOutboxDispatched(eventID string, _ int64, _ time.Time) error {
	for index := range r.pending {
		if r.pending[index].EventID == eventID {
			r.pending = append(r.pending[:index], r.pending[index+1:]...)
			break
		}
	}
	return nil
}
func (r *outboxTestRepository) MarkOutboxFailure(string, error) error { return nil }
func (r *outboxTestRepository) PendingOutboxCount() (int, error)      { return len(r.pending), nil }

func TestTransactionalOutboxDeliveryRetainsFailedEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	repository := &outboxTestRepository{base: NewMemoryRepository(), failAppend: true, pending: []auditoutbox.Intent{{EventID: "evt_outbox_test", OccurredAt: now, ActorType: "user", ActorID: "admin_test", Action: "ACCOUNT_STATUS_UPDATED", ResourceType: "user", ResourceID: "user_test", Outcome: "success", ReasonCode: "administrator_action", CorrelationID: "corr_test", ToState: "suspended"}}}
	service, err := NewService(repository, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := service.FlushOutbox(10); err == nil || delivered != 0 {
		t.Fatalf("failed delivery was not surfaced: delivered=%d err=%v", delivered, err)
	}
	if pending, _ := service.PendingOutboxCount(); pending != 1 {
		t.Fatalf("failed evidence was discarded: pending=%d", pending)
	}
	repository.failAppend = false
	if delivered, err := service.FlushOutbox(10); err != nil || delivered != 1 {
		t.Fatalf("retry did not deliver evidence: delivered=%d err=%v", delivered, err)
	}
	if pending, _ := service.PendingOutboxCount(); pending != 0 {
		t.Fatalf("delivered evidence remained pending: %d", pending)
	}
	events, _, err := repository.List(Query{Limit: 10})
	if err != nil || len(events) != 1 || events[0].EventID != "evt_outbox_test" {
		t.Fatalf("unexpected signed event: %#v err=%v", events, err)
	}
}

func TestCommittedMutationDoesNotBecomeFalseFailureWhenDeliveryIsDelayed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	repository := &outboxTestRepository{base: NewMemoryRepository(), failAppend: true, pending: []auditoutbox.Intent{{EventID: "evt_committed_test", OccurredAt: now, ActorType: "user", Action: "FILE_GRANT_REVOKED", ResourceType: "file", Outcome: "success"}}}
	service, err := NewService(repository, bytes.Repeat([]byte{0x72}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.DeliverMutationIntent(repository.pending[0], true); err != nil {
		t.Fatalf("committed mutation was reported as failed: %v", err)
	}
	if pending, _ := service.PendingOutboxCount(); pending != 1 {
		t.Fatalf("delayed evidence was not retained: pending=%d", pending)
	}
	page, err := service.List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, alert := range page.Alerts {
		if alert.ID == "audit-outbox-backlog" && alert.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("pending evidence did not produce an operational alert: %#v", page.Alerts)
	}
}

func TestAuditKeyRotationPreservesHistoricalVerification(t *testing.T) {
	repository := NewMemoryRepository()
	keys := map[string][]byte{"v1": bytes.Repeat([]byte{0x31}, 32), "v2": bytes.Repeat([]byte{0x32}, 32)}
	service, err := NewServiceWithKeyring(repository, "v1", keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(Input{ActorType: "user", Action: "BEFORE_ROTATION", ResourceType: "test", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	rotation, err := service.RotateTo("v2")
	if err != nil || rotation.KeyVersion != "v2" || rotation.FromState != "v1" {
		t.Fatalf("rotation was not chained under v2: %#v err=%v", rotation, err)
	}
	if _, err := service.Append(Input{ActorType: "user", Action: "AFTER_ROTATION", ResourceType: "test", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	verification, err := service.Verify()
	if err != nil || !verification.Valid || verification.VerifiedThrough != 3 {
		t.Fatalf("mixed-version chain did not verify: %#v err=%v", verification, err)
	}
	reconnected, err := NewServiceWithKeyring(repository, "v2", keys)
	if err != nil {
		t.Fatal(err)
	}
	if verification, err = reconnected.Verify(); err != nil || !verification.Valid {
		t.Fatalf("rotation did not survive service recreation: %#v err=%v", verification, err)
	}
	withoutHistorical, err := NewServiceWithKeyring(repository, "v2", map[string][]byte{"v2": keys["v2"]})
	if err != nil {
		t.Fatal(err)
	}
	verification, err = withoutHistorical.Verify()
	if err != nil || verification.Valid || verification.FailureCategory != "historical_key_unavailable" || verification.FirstInvalidSequence != 1 {
		t.Fatalf("missing historical key was not identified: %#v err=%v", verification, err)
	}
}

func TestSignedCheckpointAnchorDetectsTampering(t *testing.T) {
	repository := NewMemoryRepository()
	service, err := NewService(repository, bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit-checkpoints.jsonl")
	anchor, err := NewFileCheckpointAnchor(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureCheckpointAnchor(anchor, bytes.Repeat([]byte{0x62}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(Input{ActorType: "system", Action: "ANCHOR_TEST", ResourceType: "audit_chain", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	verification, err := service.Verify()
	if err != nil || !verification.Valid || !verification.Anchor.Valid || verification.Anchor.AnchoredThrough != 1 {
		t.Fatalf("signed anchor did not verify: %#v %v", verification, err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-3] ^= 1
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	verification, err = service.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if verification.Anchor.Valid || verification.Anchor.FailureCategory == "" {
		t.Fatalf("anchor tampering was not detected: %#v", verification.Anchor)
	}
}

func TestAppendVerifyAndDetectTampering(t *testing.T) {
	repository := NewMemoryRepository()
	service, err := NewService(repository, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"AUTHENTICATION", "UPLOAD_QUARANTINED", "ACCOUNT_STATUS_UPDATED"} {
		if _, err := service.Append(Input{ActorType: "user", ActorID: "usr_test", Action: action, ResourceType: "test", ResourceID: "res_1", Outcome: "success", ReasonCode: "test", CorrelationID: "corr_test"}); err != nil {
			t.Fatal(err)
		}
	}
	verification, err := service.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid || verification.EventCount != 3 || verification.VerifiedThrough != 3 {
		t.Fatalf("unexpected verification: %#v", verification)
	}
	repository.mu.Lock()
	repository.events[1].Outcome = "edited"
	repository.mu.Unlock()
	verification, err = service.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if verification.Valid || verification.FirstInvalidSequence != 2 || verification.FailureCategory != "event_mac_mismatch" {
		t.Fatalf("tampering was not detected: %#v", verification)
	}
}

func TestConcurrentAppendsRemainOrdered(t *testing.T) {
	service, err := NewService(NewMemoryRepository(), bytes.Repeat([]byte{0x72}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for index := 0; index < 30; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := service.Append(Input{ActorType: "system", Action: "CONCURRENT_TEST", ResourceType: "test", Outcome: "success", ReasonCode: "test", CorrelationID: "corr_test"}); err != nil {
				t.Errorf("append: %v", err)
			}
		}()
	}
	group.Wait()
	verification, err := service.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid || verification.EventCount != 30 {
		t.Fatalf("concurrent chain invalid: %#v", verification)
	}
}

func TestAppendNormalizesTimestampForDurableCanonicalForm(t *testing.T) {
	repository := NewMemoryRepository()
	service, err := NewService(repository, bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time {
		return time.Date(2026, time.August, 11, 21, 30, 0, 123456789, time.FixedZone("EDT", -4*60*60))
	}
	event, err := service.Append(Input{ActorType: "system", Action: "TEST", Outcome: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if event.OccurredAt.Location() != time.UTC || event.OccurredAt.Nanosecond()%1000 != 0 {
		t.Fatalf("timestamp was not normalized to UTC microseconds: %s", event.OccurredAt)
	}
	page, err := service.List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Verification.Valid {
		t.Fatalf("normalized event did not verify: %+v", page.Verification)
	}
}

func TestStructuredFiltersSummaryNetworkPrivacyAndAlerts(t *testing.T) {
	repository := NewMemoryRepository()
	service, err := NewService(repository, bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 12, 14, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	for index := 0; index < 5; index++ {
		if _, err := service.Append(Input{ActorType: "anonymous", Action: "AUTHENTICATION", ResourceType: "session", Outcome: "denied", ReasonCode: "invalid_credentials", CorrelationID: "corr_denied", NetworkAddress: "203.0.113.7"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Append(Input{ActorType: "user", ActorID: "usr_allowed", Action: "FILE_DOWNLOAD", ResourceType: "file", ResourceID: "file_1", Outcome: "success", ReasonCode: "owner_authorized", CorrelationID: "corr_success", NetworkAddress: "198.51.100.9"}); err != nil {
		t.Fatal(err)
	}

	page, err := service.List(Query{Action: "AUTHENTICATION", Outcome: "denied", NetworkAddress: "203.0.113.7", From: now.Add(-time.Hour), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 || page.Summary.Matching != 5 || page.Summary.Denied != 5 || len(page.Alerts) != 1 {
		t.Fatalf("unexpected filtered audit page: %#v", page)
	}
	for _, event := range page.Events {
		if event.NetworkSource == "" || event.NetworkSource == "203.0.113.7" {
			t.Fatalf("raw network address was exposed: %#v", event)
		}
	}
	if !page.Verification.Valid {
		t.Fatalf("network fingerprint was not protected by the chain: %#v", page.Verification)
	}
}
