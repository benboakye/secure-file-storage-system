package ingest

import (
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"securestore/internal/auditoutbox"
)

//go:embed migrations/001_ingest.sql
var ingestMigration string

//go:embed migrations/002_owner_quotas.sql
var ownerQuotaMigration string

//go:embed migrations/003_protected_statuses.sql
var protectedStatusesMigration string

//go:embed migrations/004_capacity_reservations.sql
var capacityReservationsMigration string

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
	for _, migration := range []string{ingestMigration, ownerQuotaMigration, protectedStatusesMigration, capacityReservationsMigration} {
		if _, err := pool.Exec(ctx, migration); err != nil {
			pool.Close()
			return nil, err
		}
	}
	if err := auditoutbox.Ensure(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &PostgresRepository{pool: pool}, nil
}

func (r *PostgresRepository) ReserveCapacity(request CapacityReservationRequest) error {
	if request.Bytes <= 0 || request.OwnerQuotaBytes <= 0 || request.StorageCapacityBytes <= request.StorageReserveBytes || !request.ExpiresAt.After(request.Now) {
		return ErrInvalidQuery
	}
	ctx := context.Background()
	// Read committed is intentional: the transaction acquires the global
	// advisory lock before reading usage, so every admission observes the prior
	// committed reservation without serializable-snapshot retry failures.
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The global lock serializes pool admission across API instances. The owner
	// lock additionally documents and isolates the per-account quota boundary.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(20260813,1), pg_advisory_xact_lock(20260813,hashtext($1))`, request.OwnerID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM securestore_capacity_reservations WHERE expires_at <= $1`, request.Now); err != nil {
		return err
	}
	var existingOwner string
	var existingBytes int64
	err = tx.QueryRow(ctx, `SELECT owner_id,reserved_bytes FROM securestore_capacity_reservations WHERE upload_id=$1`, request.UploadID).Scan(&existingOwner, &existingBytes)
	if err == nil {
		if existingOwner != request.OwnerID || existingBytes != request.Bytes {
			return errors.New("capacity reservation conflict")
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var ownerUsage, ownerReserved, globalUsage, globalReserved int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(u.size_bytes),0) FROM securestore_uploads u WHERE u.owner_id=$1 AND u.status IN ('quarantined','inspecting','accepted','encrypting','stored') AND NOT EXISTS(SELECT 1 FROM securestore_capacity_reservations r WHERE r.upload_id=u.id)`, request.OwnerID).Scan(&ownerUsage); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(reserved_bytes),0) FROM securestore_capacity_reservations WHERE owner_id=$1`, request.OwnerID).Scan(&ownerReserved); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(u.size_bytes),0) FROM securestore_uploads u WHERE u.status IN ('quarantined','inspecting','accepted','encrypting','stored') AND NOT EXISTS(SELECT 1 FROM securestore_capacity_reservations r WHERE r.upload_id=u.id)`).Scan(&globalUsage); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(reserved_bytes),0) FROM securestore_capacity_reservations`).Scan(&globalReserved); err != nil {
		return err
	}
	if ownerUsage+ownerReserved+request.Bytes > request.OwnerQuotaBytes {
		return ErrQuotaExceeded
	}
	if globalUsage+globalReserved+request.Bytes > request.StorageCapacityBytes-request.StorageReserveBytes {
		return ErrCapacityExceeded
	}
	if _, err := tx.Exec(ctx, `INSERT INTO securestore_capacity_reservations(upload_id,owner_id,reserved_bytes,created_at,expires_at) VALUES($1,$2,$3,$4,$5)`, request.UploadID, request.OwnerID, request.Bytes, request.Now, request.ExpiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) ReleaseCapacity(uploadID string) error {
	_, err := r.pool.Exec(context.Background(), `DELETE FROM securestore_capacity_reservations WHERE upload_id=$1`, uploadID)
	return err
}

func (r *PostgresRepository) CapacityReservationSummary(now time.Time) (CapacityReservationSummary, error) {
	result := CapacityReservationSummary{}
	err := r.pool.QueryRow(context.Background(), `SELECT count(*),COALESCE(sum(reserved_bytes),0) FROM securestore_capacity_reservations WHERE expires_at>$1`, now).Scan(&result.Active, &result.Bytes)
	return result, err
}

func (r *PostgresRepository) Close() { r.pool.Close() }

func (r *PostgresRepository) LoadAll() ([]persistedRecord, error) {
	rows, err := r.pool.Query(context.Background(), `
		SELECT id, owner_id, encode(idempotency_hash, 'hex'), name, size_bytes,
			declared_media_type, detected_media_type, status, progress,
			decision_reason, correlation_id, quarantine_object, content_digest, created_at
		FROM securestore_uploads ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]persistedRecord, 0)
	for rows.Next() {
		record, err := scanPersistedRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (r *PostgresRepository) Create(record persistedRecord) (persistedRecord, bool, error) {
	hash, err := hex.DecodeString(record.IdempotencyHash)
	if err != nil || len(hash) != 32 {
		return persistedRecord{}, false, ErrInvalidKey
	}
	_, err = r.pool.Exec(context.Background(), `
		INSERT INTO securestore_uploads
			(id, owner_id, idempotency_hash, name, size_bytes, declared_media_type,
			detected_media_type, status, progress, decision_reason, correlation_id,
			quarantine_object, content_digest, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`,
		record.ID, record.OwnerID, hash, record.Name, record.Size,
		record.DeclaredMediaType, record.DetectedMediaType, record.Status, record.Progress,
		record.DecisionReason, record.CorrelationID, record.QuarantineObject,
		record.Digest, record.CreatedAt)
	if err == nil {
		return record, false, nil
	}
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "23505" {
		return persistedRecord{}, false, err
	}
	row := r.pool.QueryRow(context.Background(), `
		SELECT id, owner_id, encode(idempotency_hash, 'hex'), name, size_bytes,
			declared_media_type, detected_media_type, status, progress,
			decision_reason, correlation_id, quarantine_object, content_digest, created_at
		FROM securestore_uploads WHERE owner_id = $1 AND idempotency_hash = $2`, record.OwnerID, hash)
	existing, scanErr := scanPersistedRecord(row)
	return existing, true, scanErr
}

func (r *PostgresRepository) Update(record persistedRecord) error {
	result, err := r.pool.Exec(context.Background(), `
		UPDATE securestore_uploads SET size_bytes=$2, detected_media_type=$3,
			status=$4, progress=$5, decision_reason=$6, content_digest=$7,
			updated_at=now() WHERE id=$1`, record.ID, record.Size,
		record.DetectedMediaType, record.Status, record.Progress,
		record.DecisionReason, record.Digest)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

func (r *PostgresRepository) UpdateAudited(record persistedRecord, intent auditoutbox.Intent) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `UPDATE securestore_uploads SET size_bytes=$2,detected_media_type=$3,status=$4,progress=$5,decision_reason=$6,content_digest=$7,updated_at=now() WHERE id=$1`, record.ID, record.Size, record.DetectedMediaType, record.Status, record.Progress, record.DecisionReason, record.Digest)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrNotFound
	}
	if err := auditoutbox.Enqueue(ctx, tx, intent); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) Delete(uploadID string) error {
	_, err := r.pool.Exec(context.Background(), `DELETE FROM securestore_uploads WHERE id = $1`, uploadID)
	return err
}

func (*PostgresRepository) Durable() bool { return true }

func (r *PostgresRepository) LoadQuotas() (map[string]int64, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT owner_id, quota_bytes FROM securestore_owner_quotas`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	quotas := make(map[string]int64)
	for rows.Next() {
		var ownerID string
		var quota int64
		if err := rows.Scan(&ownerID, &quota); err != nil {
			return nil, err
		}
		quotas[ownerID] = quota
	}
	return quotas, rows.Err()
}

func (r *PostgresRepository) SetQuota(ownerID string, quotaBytes int64) error {
	_, err := r.pool.Exec(context.Background(), `
		INSERT INTO securestore_owner_quotas (owner_id, quota_bytes, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (owner_id) DO UPDATE SET quota_bytes = EXCLUDED.quota_bytes, updated_at = EXCLUDED.updated_at`, ownerID, quotaBytes)
	return err
}

func (r *PostgresRepository) DeleteQuota(ownerID string) error {
	_, err := r.pool.Exec(context.Background(), `DELETE FROM securestore_owner_quotas WHERE owner_id = $1`, ownerID)
	return err
}

func (r *PostgresRepository) SetQuotaAudited(ownerID string, quotaBytes int64, intent auditoutbox.Intent) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO securestore_owner_quotas (owner_id,quota_bytes,updated_at) VALUES($1,$2,now()) ON CONFLICT(owner_id) DO UPDATE SET quota_bytes=EXCLUDED.quota_bytes,updated_at=EXCLUDED.updated_at`, ownerID, quotaBytes); err != nil {
		return err
	}
	if err := auditoutbox.Enqueue(ctx, tx, intent); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteQuotaAudited restores organization policy and commits its audit intent
// in the same transaction, preventing an unrecorded privileged policy change.
func (r *PostgresRepository) DeleteQuotaAudited(ownerID string, intent auditoutbox.Intent) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM securestore_owner_quotas WHERE owner_id = $1`, ownerID); err != nil {
		return err
	}
	if err := auditoutbox.Enqueue(ctx, tx, intent); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type rowScanner interface{ Scan(...any) error }

func scanPersistedRecord(row rowScanner) (persistedRecord, error) {
	var record persistedRecord
	err := row.Scan(&record.ID, &record.OwnerID, &record.IdempotencyHash, &record.Name,
		&record.Size, &record.DeclaredMediaType, &record.DetectedMediaType,
		&record.Status, &record.Progress, &record.DecisionReason,
		&record.CorrelationID, &record.QuarantineObject, &record.Digest, &record.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return persistedRecord{}, ErrNotFound
	}
	return record, err
}

var _ Repository = (*PostgresRepository)(nil)
