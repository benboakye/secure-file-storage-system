package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"securestore/internal/auditoutbox"
)

const (
	chainID           = "securestore-main-v2"
	defaultKeyVersion = "v1"
)

var genesisMAC = sha256.Sum256([]byte("securestore-audit-genesis-v2"))

type Event struct {
	Sequence      int64     `json:"sequence"`
	EventID       string    `json:"eventId"`
	OccurredAt    time.Time `json:"occurredAt"`
	ActorType     string    `json:"actorType"`
	ActorID       string    `json:"actorId"`
	Action        string    `json:"action"`
	ResourceType  string    `json:"resourceType"`
	ResourceID    string    `json:"resourceId"`
	Outcome       string    `json:"outcome"`
	ReasonCode    string    `json:"reasonCode"`
	CorrelationID string    `json:"correlationId"`
	FromState     string    `json:"fromState,omitempty"`
	ToState       string    `json:"toState,omitempty"`
	KeyVersion    string    `json:"keyVersion"`
	// NetworkSource is a keyed, non-reversible fingerprint of the client IP.
	// Raw network addresses are deliberately excluded from the audit projection.
	NetworkSource string `json:"networkSource,omitempty"`
	PreviousMAC   []byte `json:"-"`
	EventMAC      []byte `json:"-"`
}

type Input struct {
	ActorType, ActorID, Action, ResourceType, ResourceID   string
	Outcome, ReasonCode, CorrelationID, FromState, ToState string
	NetworkAddress                                         string
}

type Query struct {
	Search, ActorID, Action, ResourceType, Outcome, NetworkAddress string
	From, To                                                       time.Time
	Limit, Offset                                                  int
}

type Summary struct {
	Total          int `json:"total"`
	Matching       int `json:"matching"`
	Successful     int `json:"successful"`
	Denied         int `json:"denied"`
	Failed         int `json:"failed"`
	Last24Hours    int `json:"last24Hours"`
	DistinctActors int `json:"distinctActors"`
	HighRisk       int `json:"highRisk"`
}

type Alert struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	Detail     string    `json:"detail"`
	Count      int       `json:"count"`
	DetectedAt time.Time `json:"detectedAt"`
}

type Checkpoint struct {
	ChainID, KeyVersion string
	LastSequence        int64
	LastMAC             []byte
	UpdatedAt           time.Time
}

type Verification struct {
	Valid                bool               `json:"valid"`
	EventCount           int                `json:"eventCount"`
	VerifiedThrough      int64              `json:"verifiedThrough"`
	CheckpointAt         time.Time          `json:"checkpointAt,omitempty"`
	CheckpointTrust      string             `json:"checkpointTrust"`
	FailureCategory      string             `json:"failureCategory,omitempty"`
	FirstInvalidSequence int64              `json:"firstInvalidSequence,omitempty"`
	Anchor               AnchorVerification `json:"anchor"`
}

type AnchorVerification struct {
	Connected       bool      `json:"connected"`
	ProductionReady bool      `json:"productionReady"`
	Adapter         string    `json:"adapter"`
	Detail          string    `json:"detail"`
	Valid           bool      `json:"valid"`
	AnchoredThrough int64     `json:"anchoredThrough"`
	AnchoredAt      time.Time `json:"anchoredAt,omitempty"`
	FailureCategory string    `json:"failureCategory,omitempty"`
}

type Page struct {
	Events       []Event      `json:"events"`
	Total        int          `json:"total"`
	Limit        int          `json:"limit"`
	Offset       int          `json:"offset"`
	Verification Verification `json:"verification"`
	Summary      Summary      `json:"summary"`
	Alerts       []Alert      `json:"alerts"`
}

type Repository interface {
	Append(Event, func(int64, []byte, Event) []byte) (Event, error)
	LoadChain() ([]Event, Checkpoint, error)
	List(Query) ([]Event, int, error)
	Summary(Query, time.Time) (Summary, error)
	Durable() bool
}

type Service struct {
	repository        Repository
	keys              map[string][]byte
	currentKeyVersion string
	anchor            CheckpointAnchor
	anchorKey         []byte
	now               func() time.Time
}

type outboxRepository interface {
	PendingOutbox(int) ([]auditoutbox.Intent, error)
	MarkOutboxDispatched(string, int64, time.Time) error
	MarkOutboxFailure(string, error) error
	PendingOutboxCount() (int, error)
}

func NewService(repository Repository, key []byte) (*Service, error) {
	return NewServiceWithKeyring(repository, defaultKeyVersion, map[string][]byte{defaultKeyVersion: key})
}

func NewServiceWithKeyring(repository Repository, currentVersion string, keys map[string][]byte) (*Service, error) {
	currentVersion = safe(currentVersion)
	if repository == nil || currentVersion == "" || len(keys[currentVersion]) < 32 {
		return nil, errors.New("audit repository and a key of at least 32 bytes are required")
	}
	cloned := make(map[string][]byte, len(keys))
	for version, key := range keys {
		version = safe(version)
		if version == "" || len(key) < 32 {
			return nil, errors.New("every audit key requires a safe version and at least 32 bytes")
		}
		cloned[version] = append([]byte(nil), key...)
	}
	active := currentVersion
	_, checkpoint, err := repository.LoadChain()
	if err != nil {
		return nil, err
	}
	if checkpoint.LastSequence > 0 {
		active = checkpoint.KeyVersion
		if len(cloned[active]) < 32 {
			return nil, errors.New("current audit checkpoint requires an unavailable historical key")
		}
	}
	return &Service{repository: repository, keys: cloned, currentKeyVersion: active, now: time.Now}, nil
}

// RotateTo appends a chained transition under the new key. Because the event's
// previous MAC is the old chain head, it cryptographically joins both key eras.
// A failed append restores the old write version and leaves the chain unchanged.
func (s *Service) RotateTo(version string) (Event, error) {
	version = safe(version)
	if version == "" || len(s.keys[version]) < 32 {
		return Event{}, errors.New("requested audit key version is unavailable")
	}
	if version == s.currentKeyVersion {
		return Event{}, nil
	}
	previous := s.currentKeyVersion
	s.currentKeyVersion = version
	event, err := s.Append(Input{ActorType: "system", ActorID: "audit-key-manager", Action: "AUDIT_KEY_ROTATED", ResourceType: "audit_key", ResourceID: version, Outcome: "success", ReasonCode: "configured_key_rotation", FromState: previous, ToState: version})
	if err != nil {
		s.currentKeyVersion = previous
		return Event{}, err
	}
	return event, nil
}

func (s *Service) CurrentKeyVersion() string { return s.currentKeyVersion }

func (s *Service) ConfigureCheckpointAnchor(anchor CheckpointAnchor, key []byte) error {
	if anchor == nil {
		return errors.New("checkpoint anchor is required")
	}
	// Remote anchors verify receipts with a pinned public key and never load an
	// anchor signing secret into SecureStore. Local development adapters retain
	// the separate HMAC key so the existing on-host evidence remains testable.
	if _, externallyAttested := anchor.(anchorReceiptVerifier); !externallyAttested && len(key) < 32 {
		return errors.New("local checkpoint anchors require a separate key of at least 32 bytes")
	}
	s.anchor, s.anchorKey = anchor, append([]byte(nil), key...)
	return nil
}

func DecodeKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(key) < 32 {
		return nil, errors.New("SECURESTORE_AUDIT_HMAC_KEY must be base64 for at least 32 random bytes")
	}
	return key, nil
}

func (s *Service) Append(input Input) (Event, error) {
	id, err := opaqueID()
	if err != nil {
		return Event{}, err
	}
	// PostgreSQL timestamps preserve microseconds, not Go's full nanosecond
	// precision. Normalize before signing so a durable event has identical
	// canonical bytes before and after a database/process round trip.
	event := Event{
		EventID: id, OccurredAt: s.now().UTC().Truncate(time.Microsecond), ActorType: safe(input.ActorType), ActorID: safe(input.ActorID),
		Action: safe(input.Action), ResourceType: safe(input.ResourceType), ResourceID: safe(input.ResourceID),
		Outcome: safe(input.Outcome), ReasonCode: safe(input.ReasonCode), CorrelationID: safe(input.CorrelationID),
		FromState: safe(input.FromState), ToState: safe(input.ToState), KeyVersion: s.currentKeyVersion,
	}
	event.NetworkSource = s.networkFingerprint(input.NetworkAddress)
	return s.appendEvent(event)
}

// NewMutationIntent creates the stable identity used by both the transactional
// outbox row and its eventual signed-chain event.
func (s *Service) NewMutationIntent(input Input) (auditoutbox.Intent, error) {
	id, err := opaqueID()
	if err != nil {
		return auditoutbox.Intent{}, err
	}
	return auditoutbox.Intent{EventID: id, OccurredAt: s.now().UTC().Truncate(time.Microsecond), ActorType: safe(input.ActorType), ActorID: safe(input.ActorID), Action: safe(input.Action), ResourceType: safe(input.ResourceType), ResourceID: safe(input.ResourceID), Outcome: safe(input.Outcome), ReasonCode: safe(input.ReasonCode), CorrelationID: safe(input.CorrelationID), FromState: safe(input.FromState), ToState: safe(input.ToState)}, nil
}

// DeliverMutationIntent synchronously drains durable evidence after commit. In
// the in-memory development repository there is no transactional outbox, so it
// appends the same stable event directly.
func (s *Service) DeliverMutationIntent(intent auditoutbox.Intent, durable bool) error {
	if durable {
		// The protected mutation and its evidence are already committed. An
		// immediate delivery attempt reduces latency, but failure must not produce
		// a false-negative HTTP response that encourages a duplicate mutation.
		// The durable row remains pending, monitoring raises an alert, and the
		// background dispatcher retries it.
		_, _ = s.FlushOutbox(100)
		return nil
	}
	_, err := s.appendEvent(Event{EventID: intent.EventID, OccurredAt: intent.OccurredAt, ActorType: intent.ActorType, ActorID: intent.ActorID, Action: intent.Action, ResourceType: intent.ResourceType, ResourceID: intent.ResourceID, Outcome: intent.Outcome, ReasonCode: intent.ReasonCode, CorrelationID: intent.CorrelationID, FromState: intent.FromState, ToState: intent.ToState, KeyVersion: s.currentKeyVersion})
	return err
}

func (s *Service) appendEvent(event Event) (Event, error) {
	committed, err := s.repository.Append(event, s.computeMAC)
	if err != nil {
		return Event{}, err
	}
	if s.anchor != nil {
		record := AnchorRecord{ChainID: chainID, Sequence: committed.Sequence, Checkpoint: base64.RawURLEncoding.EncodeToString(committed.EventMAC), PreviousCheckpoint: base64.RawURLEncoding.EncodeToString(committed.PreviousMAC), KeyVersion: committed.KeyVersion, AnchoredAt: s.now().UTC().Truncate(time.Microsecond)}
		if _, externallyAttested := s.anchor.(anchorReceiptVerifier); !externallyAttested {
			record.Signature = signAnchor(s.anchorKey, record)
		}
		if err := s.anchor.Append(record); err != nil {
			// The database event remains authoritative and committed. Verification
			// reports anchor lag/failure instead of pretending the append rolled back.
			return committed, nil
		}
	}
	return committed, nil
}

// FlushOutbox delivers committed mutation evidence to the signed chain. A
// stable event ID makes delivery idempotent across crashes between append and
// acknowledgement. Failed rows remain durable for the next retry.
func (s *Service) FlushOutbox(limit int) (int, error) {
	repository, ok := s.repository.(outboxRepository)
	if !ok {
		return 0, nil
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	intents, err := repository.PendingOutbox(limit)
	if err != nil {
		return 0, err
	}
	delivered := 0
	for _, intent := range intents {
		event := Event{EventID: safe(intent.EventID), OccurredAt: intent.OccurredAt.UTC().Truncate(time.Microsecond), ActorType: safe(intent.ActorType), ActorID: safe(intent.ActorID), Action: safe(intent.Action), ResourceType: safe(intent.ResourceType), ResourceID: safe(intent.ResourceID), Outcome: safe(intent.Outcome), ReasonCode: safe(intent.ReasonCode), CorrelationID: safe(intent.CorrelationID), FromState: safe(intent.FromState), ToState: safe(intent.ToState), KeyVersion: s.currentKeyVersion}
		committed, appendErr := s.appendEvent(event)
		if appendErr != nil {
			_ = repository.MarkOutboxFailure(intent.EventID, appendErr)
			return delivered, appendErr
		}
		if err := repository.MarkOutboxDispatched(intent.EventID, committed.Sequence, s.now().UTC().Truncate(time.Microsecond)); err != nil {
			return delivered, err
		}
		delivered++
	}
	return delivered, nil
}

func (s *Service) PendingOutboxCount() (int, error) {
	repository, ok := s.repository.(outboxRepository)
	if !ok {
		return 0, nil
	}
	return repository.PendingOutboxCount()
}

func (s *Service) List(query Query) (Page, error) {
	query.Search = strings.TrimSpace(query.Search)
	query.ActorID = safe(query.ActorID)
	query.Action = safe(query.Action)
	query.ResourceType = safe(query.ResourceType)
	query.Outcome = safe(query.Outcome)
	if len(query.Search) > 120 {
		return Page{}, errors.New("invalid audit search")
	}
	if query.Limit < 1 || query.Limit > 100 {
		query.Limit = 50
	}
	if query.Offset < 0 {
		query.Offset = 0
	}
	if !query.From.IsZero() && !query.To.IsZero() && query.From.After(query.To) {
		return Page{}, errors.New("invalid audit date range")
	}
	query.NetworkAddress = s.networkFingerprint(query.NetworkAddress)
	events, total, err := s.repository.List(query)
	if err != nil {
		return Page{}, err
	}
	summary, err := s.repository.Summary(query, s.now().UTC())
	if err != nil {
		return Page{}, err
	}
	verification, err := s.Verify()
	if err != nil {
		return Page{}, err
	}
	alerts, err := s.alerts(verification)
	if err != nil {
		return Page{}, err
	}
	return Page{Events: events, Total: total, Limit: query.Limit, Offset: query.Offset, Verification: verification, Summary: summary, Alerts: alerts}, nil
}

// Export returns a bounded safe projection. The caller is responsible for
// recording the export request before releasing any evidence to the client.
func (s *Service) Export(query Query, maximum int) ([]Event, Verification, error) {
	query.Search = strings.TrimSpace(query.Search)
	if len(query.Search) > 120 || (!query.From.IsZero() && !query.To.IsZero() && query.From.After(query.To)) {
		return nil, Verification{}, errors.New("invalid audit query")
	}
	if maximum < 1 || maximum > 10000 {
		maximum = 5000
	}
	query.Limit, query.Offset = maximum, 0
	query.ActorID, query.Action = safe(query.ActorID), safe(query.Action)
	query.ResourceType, query.Outcome = safe(query.ResourceType), safe(query.Outcome)
	query.NetworkAddress = s.networkFingerprint(query.NetworkAddress)
	events, _, err := s.repository.List(query)
	if err != nil {
		return nil, Verification{}, err
	}
	verification, err := s.Verify()
	return events, verification, err
}

func (s *Service) alerts(verification Verification) ([]Alert, error) {
	now := s.now().UTC()
	window := now.Add(-15 * time.Minute)
	alerts := make([]Alert, 0)
	checks := []struct {
		query     Query
		threshold int
		alert     Alert
	}{
		{Query{Action: "AUTHENTICATION", Outcome: "denied", From: window, Limit: 1}, 5, Alert{ID: "repeated-authentication-denials", Type: "authentication", Severity: "high", Title: "Repeated sign-in denials", Detail: "Five or more denied authentication attempts occurred within 15 minutes."}},
		{Query{Action: "FILE_DOWNLOAD", Outcome: "denied", From: window, Limit: 1}, 3, Alert{ID: "repeated-download-denials", Type: "file_access", Severity: "high", Title: "Repeated download denials", Detail: "Three or more denied file-download attempts occurred within 15 minutes."}},
	}
	for _, check := range checks {
		_, count, err := s.repository.List(check.query)
		if err != nil {
			return nil, err
		}
		if count >= check.threshold {
			check.alert.Count, check.alert.DetectedAt = count, now
			alerts = append(alerts, check.alert)
		}
	}
	if !verification.Valid {
		alerts = append(alerts, Alert{ID: "audit-integrity-failure", Type: "audit_integrity", Severity: "critical", Title: "Audit integrity verification failed", Detail: "The ordered audit chain no longer agrees with its checkpoint.", Count: 1, DetectedAt: now})
	}
	if verification.Anchor.Connected && !verification.Anchor.Valid {
		alerts = append(alerts, Alert{ID: "audit-anchor-failure", Type: "audit_anchor", Severity: "critical", Title: "Audit checkpoint anchor requires attention", Detail: "The signed checkpoint anchor is unavailable, invalid, or does not match the database checkpoint.", Count: 1, DetectedAt: now})
	}
	pending, err := s.PendingOutboxCount()
	if err != nil {
		return nil, err
	}
	if pending > 0 {
		alerts = append(alerts, Alert{ID: "audit-outbox-backlog", Type: "audit_delivery", Severity: "high", Title: "Committed audit evidence is awaiting delivery", Detail: "One or more protected mutations are durable but have not yet reached the signed audit chain.", Count: pending, DetectedAt: now})
	}
	return alerts, nil
}

func (s *Service) Verify() (Verification, error) {
	events, checkpoint, err := s.repository.LoadChain()
	if err != nil {
		return Verification{}, err
	}
	anchor := s.anchorVerification(checkpoint)
	trust := "database-backed checkpoint only"
	if anchor.Connected {
		trust = "database checkpoint with separately signed anchor evidence"
	}
	result := Verification{Valid: true, EventCount: len(events), CheckpointTrust: trust, CheckpointAt: checkpoint.UpdatedAt, Anchor: anchor}
	previous := genesisMAC[:]
	for index, event := range events {
		expectedSequence := int64(index + 1)
		if event.Sequence != expectedSequence {
			return invalid(result, expectedSequence, "sequence_discontinuity"), nil
		}
		if !hmac.Equal(event.PreviousMAC, previous) {
			return invalid(result, event.Sequence, "previous_mac_mismatch"), nil
		}
		if _, ok := s.keys[event.KeyVersion]; !ok {
			return invalid(result, event.Sequence, "historical_key_unavailable"), nil
		}
		expected := s.computeMAC(event.Sequence, previous, event)
		if !hmac.Equal(event.EventMAC, expected) {
			return invalid(result, event.Sequence, "event_mac_mismatch"), nil
		}
		previous = event.EventMAC
		result.VerifiedThrough = event.Sequence
	}
	if checkpoint.LastSequence != int64(len(events)) || !hmac.Equal(checkpoint.LastMAC, previous) {
		return invalid(result, checkpoint.LastSequence, "checkpoint_mismatch"), nil
	}
	return result, nil
}

func (s *Service) anchorVerification(checkpoint Checkpoint) AnchorVerification {
	if s.anchor == nil {
		return AnchorVerification{Detail: "No independent checkpoint anchor is configured.", FailureCategory: "not_configured"}
	}
	posture := s.anchor.Posture()
	result := AnchorVerification{Connected: posture.Connected, ProductionReady: posture.ProductionReady, Adapter: posture.Adapter, Detail: posture.Detail}
	record, err := s.anchor.Latest()
	if err != nil {
		result.FailureCategory = "anchor_unavailable"
		return result
	}
	result.AnchoredThrough, result.AnchoredAt = record.Sequence, record.AnchoredAt
	validReceipt := validAnchorSignature(s.anchorKey, record)
	if verifier, externallyAttested := s.anchor.(anchorReceiptVerifier); externallyAttested {
		validReceipt = verifier.VerifyReceipt(record)
	}
	if !validReceipt {
		result.FailureCategory = "anchor_signature_invalid"
		return result
	}
	checkpointMAC, err := base64.RawURLEncoding.DecodeString(record.Checkpoint)
	if err != nil || record.ChainID != checkpoint.ChainID || record.KeyVersion != checkpoint.KeyVersion || record.Sequence != checkpoint.LastSequence || !hmac.Equal(checkpointMAC, checkpoint.LastMAC) {
		result.FailureCategory = "anchor_checkpoint_mismatch"
		return result
	}
	result.Valid = true
	return result
}

func (s *Service) Durable() bool { return s.repository.Durable() }

func invalid(result Verification, sequence int64, category string) Verification {
	result.Valid = false
	result.FirstInvalidSequence = sequence
	result.FailureCategory = category
	return result
}

func (s *Service) computeMAC(sequence int64, previous []byte, event Event) []byte {
	key := s.keys[event.KeyVersion]
	mac := hmac.New(sha256.New, key)
	writeField(mac, []byte("securestore.audit.chain.v2"))
	_ = binary.Write(mac, binary.BigEndian, sequence)
	writeField(mac, previous)
	writeField(mac, canonicalEvent(event))
	return mac.Sum(nil)
}

func canonicalEvent(event Event) []byte {
	var buffer bytes.Buffer
	for _, value := range []string{event.EventID, event.OccurredAt.UTC().Format(time.RFC3339Nano), event.ActorType, event.ActorID, event.Action, event.ResourceType, event.ResourceID, event.Outcome, event.ReasonCode, event.CorrelationID, event.FromState, event.ToState, event.KeyVersion} {
		writeField(&buffer, []byte(value))
	}
	// Network fingerprints were added after the v2 chain was deployed. Omitting
	// an empty value preserves the canonical bytes of historical events, while a
	// present fingerprint remains covered by the event MAC.
	if event.NetworkSource != "" {
		writeField(&buffer, []byte(event.NetworkSource))
	}
	return buffer.Bytes()
}

func (s *Service) networkFingerprint(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	mac := hmac.New(sha256.New, s.keys[s.currentKeyVersion])
	writeField(mac, []byte("securestore.audit.network.v1"))
	writeField(mac, []byte(address))
	return "net_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
}

type writer interface{ Write([]byte) (int, error) }

func writeField(destination writer, value []byte) {
	_ = binary.Write(destination, binary.BigEndian, uint32(len(value)))
	_, _ = destination.Write(value)
}
func safe(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 160 {
		return value[:160]
	}
	return value
}
func opaqueID() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "aud_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
