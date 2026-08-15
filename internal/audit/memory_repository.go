package audit

import (
	"strings"
	"sync"
	"time"
)

type MemoryRepository struct {
	mu         sync.Mutex
	events     []Event
	checkpoint Checkpoint
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{events: make([]Event, 0), checkpoint: Checkpoint{ChainID: chainID, KeyVersion: defaultKeyVersion, LastMAC: append([]byte(nil), genesisMAC[:]...)}}
}

func (r *MemoryRepository) Durable() bool { return false }

func (r *MemoryRepository) Append(event Event, compute func(int64, []byte, Event) []byte) (Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// PostgreSQL enforces a unique event_id. Mirror that idempotency boundary in
	// development so retries cannot produce evidence that would be impossible in
	// the durable repository.
	if event.EventID != "" {
		for _, existing := range r.events {
			if existing.EventID == event.EventID {
				return cloneEvent(existing), nil
			}
		}
	}
	event.Sequence = int64(len(r.events) + 1)
	event.PreviousMAC = append([]byte(nil), r.checkpoint.LastMAC...)
	event.EventMAC = compute(event.Sequence, event.PreviousMAC, event)
	r.events = append(r.events, cloneEvent(event))
	r.checkpoint = Checkpoint{ChainID: chainID, LastSequence: event.Sequence, LastMAC: append([]byte(nil), event.EventMAC...), KeyVersion: event.KeyVersion, UpdatedAt: event.OccurredAt}
	return cloneEvent(event), nil
}

func (r *MemoryRepository) LoadChain() ([]Event, Checkpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	events := make([]Event, len(r.events))
	for i := range r.events {
		events[i] = cloneEvent(r.events[i])
	}
	checkpoint := r.checkpoint
	checkpoint.LastMAC = append([]byte(nil), checkpoint.LastMAC...)
	return events, checkpoint, nil
}

func (r *MemoryRepository) List(query Query) ([]Event, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	matches := make([]Event, 0)
	for index := len(r.events) - 1; index >= 0; index-- {
		event := r.events[index]
		if matchesQuery(event, query) {
			matches = append(matches, cloneEvent(event))
		}
	}
	total := len(matches)
	if query.Offset >= total {
		return []Event{}, total, nil
	}
	end := query.Offset + query.Limit
	if end > total {
		end = total
	}
	return matches[query.Offset:end], total, nil
}

func (r *MemoryRepository) Summary(query Query, now time.Time) (Summary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := Summary{Total: len(r.events)}
	actors := make(map[string]struct{})
	for _, event := range r.events {
		if !matchesQuery(event, query) {
			continue
		}
		result.Matching++
		switch event.Outcome {
		case "success":
			result.Successful++
		case "denied":
			result.Denied++
		case "failed":
			result.Failed++
		}
		if !event.OccurredAt.Before(now.Add(-24 * time.Hour)) {
			result.Last24Hours++
		}
		if event.ActorID != "" {
			actors[event.ActorID] = struct{}{}
		}
		if highRisk(event) {
			result.HighRisk++
		}
	}
	result.DistinctActors = len(actors)
	return result, nil
}

func matchesQuery(event Event, query Query) bool {
	search := strings.ToLower(query.Search)
	joined := strings.ToLower(event.Action + " " + event.ActorID + " " + event.ResourceType + " " + event.ResourceID + " " + event.Outcome + " " + event.ReasonCode + " " + event.CorrelationID + " " + event.NetworkSource)
	return (search == "" || strings.Contains(joined, search)) &&
		(query.ActorID == "" || strings.EqualFold(event.ActorID, query.ActorID)) &&
		(query.Action == "" || strings.EqualFold(event.Action, query.Action)) &&
		(query.ResourceType == "" || strings.EqualFold(event.ResourceType, query.ResourceType)) &&
		(query.Outcome == "" || strings.EqualFold(event.Outcome, query.Outcome)) &&
		(query.NetworkAddress == "" || event.NetworkSource == query.NetworkAddress) &&
		(query.From.IsZero() || !event.OccurredAt.Before(query.From)) &&
		(query.To.IsZero() || !event.OccurredAt.After(query.To))
}

func highRisk(event Event) bool {
	return event.Outcome == "failed" || event.Outcome == "denied" || event.Action == "ACCOUNT_STATUS_UPDATED" || event.Action == "OWNER_QUOTA_UPDATED" || event.Action == "FILE_GRANT_REVOKED" || event.Action == "FILE_CRYPTOGRAPHICALLY_DELETED" || event.Action == "LEGAL_HOLD_UPDATED"
}

func cloneEvent(event Event) Event {
	event.PreviousMAC = append([]byte(nil), event.PreviousMAC...)
	event.EventMAC = append([]byte(nil), event.EventMAC...)
	return event
}
