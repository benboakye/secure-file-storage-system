// Package auditoutbox defines the deliberately small, sanitized contract used
// to couple security-sensitive database mutations to durable audit evidence.
// It contains no credentials, tokens, file contents, or raw network addresses.
package auditoutbox

import (
	"context"
	_ "embed"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migration.sql
var migration string

// Intent is written in the same transaction as the protected state change.
// EventID is stable so retrying delivery cannot create a second chain event.
type Intent struct {
	EventID, ActorType, ActorID, Action, ResourceType, ResourceID string
	Outcome, ReasonCode, CorrelationID, FromState, ToState        string
	OccurredAt                                                    time.Time
}

func (i Intent) Validate() error {
	for _, value := range []string{i.EventID, i.ActorType, i.Action, i.ResourceType, i.Outcome} {
		if strings.TrimSpace(value) == "" {
			return errors.New("invalid audit outbox intent")
		}
	}
	if i.OccurredAt.IsZero() {
		return errors.New("audit outbox intent requires a timestamp")
	}
	return nil
}

// Ensure installs the shared outbox before any repository attempts an audited
// mutation. CREATE IF NOT EXISTS makes initialization order irrelevant.
func Ensure(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, migration)
	return err
}

// Enqueue adds the evidence inside the caller's active mutation transaction.
func Enqueue(ctx context.Context, tx pgx.Tx, intent Intent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO securestore_audit_outbox
		(event_id,occurred_at,actor_type,actor_id,action,resource_type,resource_id,outcome,reason_code,correlation_id,from_state,to_state)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT(event_id) DO NOTHING`, intent.EventID, intent.OccurredAt, intent.ActorType,
		intent.ActorID, intent.Action, intent.ResourceType, intent.ResourceID, intent.Outcome,
		intent.ReasonCode, intent.CorrelationID, intent.FromState, intent.ToState)
	return err
}
