package audit

import (
	"context"
	_ "embed"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"securestore/internal/auditoutbox"
)

//go:embed migrations/001_audit.sql
var auditMigration string

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(ctx context.Context, databaseURL string) (*PostgresRepository, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if _, err := pool.Exec(ctx, auditMigration); err != nil {
		pool.Close()
		return nil, err
	}
	if err := auditoutbox.Ensure(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &PostgresRepository{pool: pool}, nil
}
func (r *PostgresRepository) Close()        { r.pool.Close() }
func (r *PostgresRepository) Durable() bool { return true }

func (r *PostgresRepository) Append(event Event, compute func(int64, []byte, Event) []byte) (Event, error) {
	ctx := context.Background()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Event{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('securestore-audit-v2'))`); err != nil {
		return Event{}, err
	}
	var sequence int64
	previous := append([]byte(nil), genesisMAC[:]...)
	err = tx.QueryRow(ctx, `SELECT last_sequence, last_mac FROM securestore_audit_checkpoint_v2 WHERE chain_id=$1 FOR UPDATE`, chainID).Scan(&sequence, &previous)
	if err != nil && err != pgx.ErrNoRows {
		return Event{}, err
	}
	sequence++
	event.Sequence = sequence
	event.PreviousMAC = previous
	event.EventMAC = compute(sequence, previous, event)
	_, err = tx.Exec(ctx, `INSERT INTO securestore_audit_events_v2 (sequence,event_id,occurred_at,actor_type,actor_id,action,resource_type,resource_id,outcome,reason_code,correlation_id,from_state,to_state,key_version,previous_mac,event_mac,network_source) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, event.Sequence, event.EventID, event.OccurredAt, event.ActorType, event.ActorID, event.Action, event.ResourceType, event.ResourceID, event.Outcome, event.ReasonCode, event.CorrelationID, event.FromState, event.ToState, event.KeyVersion, event.PreviousMAC, event.EventMAC, event.NetworkSource)
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			_ = tx.Rollback(ctx)
			existing, scanErr := scanEvent(r.pool.QueryRow(ctx, `SELECT sequence,event_id,occurred_at,actor_type,actor_id,action,resource_type,resource_id,outcome,reason_code,correlation_id,from_state,to_state,key_version,previous_mac,event_mac,network_source FROM securestore_audit_events_v2 WHERE event_id=$1`, event.EventID))
			return existing, scanErr
		}
		return Event{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO securestore_audit_checkpoint_v2 (chain_id,last_sequence,last_mac,key_version,updated_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (chain_id) DO UPDATE SET last_sequence=EXCLUDED.last_sequence,last_mac=EXCLUDED.last_mac,key_version=EXCLUDED.key_version,updated_at=EXCLUDED.updated_at`, chainID, event.Sequence, event.EventMAC, event.KeyVersion, event.OccurredAt)
	if err != nil {
		return Event{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Event{}, err
	}
	return event, nil
}

func (r *PostgresRepository) PendingOutbox(limit int) ([]auditoutbox.Intent, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT event_id,occurred_at,actor_type,actor_id,action,resource_type,resource_id,outcome,reason_code,correlation_id,from_state,to_state FROM securestore_audit_outbox WHERE dispatched_at IS NULL ORDER BY occurred_at,event_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	intents := make([]auditoutbox.Intent, 0)
	for rows.Next() {
		var intent auditoutbox.Intent
		if err := rows.Scan(&intent.EventID, &intent.OccurredAt, &intent.ActorType, &intent.ActorID, &intent.Action, &intent.ResourceType, &intent.ResourceID, &intent.Outcome, &intent.ReasonCode, &intent.CorrelationID, &intent.FromState, &intent.ToState); err != nil {
			return nil, err
		}
		intents = append(intents, intent)
	}
	return intents, rows.Err()
}

func (r *PostgresRepository) MarkOutboxDispatched(eventID string, sequence int64, now time.Time) error {
	_, err := r.pool.Exec(context.Background(), `UPDATE securestore_audit_outbox SET dispatched_at=$2,chain_sequence=$3,last_error='',attempts=attempts+1 WHERE event_id=$1 AND dispatched_at IS NULL`, eventID, now, sequence)
	return err
}

func (r *PostgresRepository) MarkOutboxFailure(eventID string, failure error) error {
	message := failure.Error()
	if len(message) > 240 {
		message = message[:240]
	}
	_, err := r.pool.Exec(context.Background(), `UPDATE securestore_audit_outbox SET attempts=attempts+1,last_error=$2 WHERE event_id=$1 AND dispatched_at IS NULL`, eventID, message)
	return err
}

func (r *PostgresRepository) PendingOutboxCount() (int, error) {
	var count int
	err := r.pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_audit_outbox WHERE dispatched_at IS NULL`).Scan(&count)
	return count, err
}

func (r *PostgresRepository) LoadChain() ([]Event, Checkpoint, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT sequence,event_id,occurred_at,actor_type,actor_id,action,resource_type,resource_id,outcome,reason_code,correlation_id,from_state,to_state,key_version,previous_mac,event_mac,network_source FROM securestore_audit_events_v2 ORDER BY sequence`)
	if err != nil {
		return nil, Checkpoint{}, err
	}
	defer rows.Close()
	events := make([]Event, 0)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, Checkpoint{}, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, Checkpoint{}, err
	}
	cp := Checkpoint{ChainID: chainID, KeyVersion: defaultKeyVersion, LastMAC: append([]byte(nil), genesisMAC[:]...)}
	err = r.pool.QueryRow(context.Background(), `SELECT last_sequence,last_mac,key_version,updated_at FROM securestore_audit_checkpoint_v2 WHERE chain_id=$1`, chainID).Scan(&cp.LastSequence, &cp.LastMAC, &cp.KeyVersion, &cp.UpdatedAt)
	if err != nil && err != pgx.ErrNoRows {
		return nil, Checkpoint{}, err
	}
	return events, cp, nil
}

func (r *PostgresRepository) List(query Query) ([]Event, int, error) {
	pattern := "%" + strings.ToLower(query.Search) + "%"
	ctx := context.Background()
	var total int
	filter := `($1='' OR lower(action||' '||actor_id||' '||resource_type||' '||resource_id||' '||outcome||' '||reason_code||' '||correlation_id||' '||network_source) LIKE $2)
		AND ($3='' OR lower(actor_id)=lower($3)) AND ($4='' OR lower(action)=lower($4))
		AND ($5='' OR lower(resource_type)=lower($5)) AND ($6='' OR lower(outcome)=lower($6))
		AND ($7='' OR network_source=$7) AND ($8::timestamptz IS NULL OR occurred_at >= $8)
		AND ($9::timestamptz IS NULL OR occurred_at <= $9)`
	args := []any{query.Search, pattern, query.ActorID, query.Action, query.ResourceType, query.Outcome, query.NetworkAddress, nullableTime(query.From), nullableTime(query.To)}
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM securestore_audit_events_v2 WHERE `+filter, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, query.Limit, query.Offset)
	rows, err := r.pool.Query(ctx, `SELECT sequence,event_id,occurred_at,actor_type,actor_id,action,resource_type,resource_id,outcome,reason_code,correlation_id,from_state,to_state,key_version,previous_mac,event_mac,network_source FROM securestore_audit_events_v2 WHERE `+filter+` ORDER BY sequence DESC LIMIT $10 OFFSET $11`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	events := make([]Event, 0)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, total, rows.Err()
}

func (r *PostgresRepository) Summary(query Query, now time.Time) (Summary, error) {
	pattern := "%" + strings.ToLower(query.Search) + "%"
	filter := `($1='' OR lower(action||' '||actor_id||' '||resource_type||' '||resource_id||' '||outcome||' '||reason_code||' '||correlation_id||' '||network_source) LIKE $2)
		AND ($3='' OR lower(actor_id)=lower($3)) AND ($4='' OR lower(action)=lower($4))
		AND ($5='' OR lower(resource_type)=lower($5)) AND ($6='' OR lower(outcome)=lower($6))
		AND ($7='' OR network_source=$7) AND ($8::timestamptz IS NULL OR occurred_at >= $8)
		AND ($9::timestamptz IS NULL OR occurred_at <= $9)`
	var result Summary
	err := r.pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM securestore_audit_events_v2), count(*),
		count(*) FILTER (WHERE outcome='success'), count(*) FILTER (WHERE outcome='denied'),
		count(*) FILTER (WHERE outcome='failed'), count(*) FILTER (WHERE occurred_at >= $10),
		count(DISTINCT NULLIF(actor_id,'')), count(*) FILTER (WHERE outcome IN ('denied','failed') OR action IN ('ACCOUNT_STATUS_UPDATED','OWNER_QUOTA_UPDATED','FILE_GRANT_REVOKED','FILE_CRYPTOGRAPHICALLY_DELETED','LEGAL_HOLD_UPDATED'))
		FROM securestore_audit_events_v2 WHERE `+filter,
		query.Search, pattern, query.ActorID, query.Action, query.ResourceType, query.Outcome, query.NetworkAddress, nullableTime(query.From), nullableTime(query.To), now.Add(-24*time.Hour)).Scan(
		&result.Total, &result.Matching, &result.Successful, &result.Denied, &result.Failed, &result.Last24Hours, &result.DistinctActors, &result.HighRisk)
	return result, err
}

type rowScanner interface{ Scan(...any) error }

func scanEvent(row rowScanner) (Event, error) {
	var event Event
	err := row.Scan(&event.Sequence, &event.EventID, &event.OccurredAt, &event.ActorType, &event.ActorID, &event.Action, &event.ResourceType, &event.ResourceID, &event.Outcome, &event.ReasonCode, &event.CorrelationID, &event.FromState, &event.ToState, &event.KeyVersion, &event.PreviousMAC, &event.EventMAC, &event.NetworkSource)
	return event, err
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
