package protectedstore

import (
	"context"
	_ "embed"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"securestore/internal/auditoutbox"
)

//go:embed migrations/001_protected_store.sql
var protectedStoreMigration string

//go:embed migrations/002_file_catalog.sql
var fileCatalogMigration string

//go:embed migrations/003_access_grants.sql
var accessGrantsMigration string

//go:embed migrations/004_file_lifecycle.sql
var fileLifecycleMigration string

//go:embed migrations/005_dek_rewrap.sql
var dekRewrapMigration string

//go:embed migrations/006_orphan_reconciliation.sql
var orphanReconciliationMigration string

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
	for _, migration := range []string{protectedStoreMigration, fileCatalogMigration, accessGrantsMigration, fileLifecycleMigration, dekRewrapMigration, orphanReconciliationMigration} {
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

func (r *PostgresRepository) AuthorizeOrphanReconciliation(operation OrphanReconciliationOperation, intent auditoutbox.Intent) (OrphanReconciliationOperation, bool, error) {
	ctx := context.Background()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return OrphanReconciliationOperation{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, `INSERT INTO securestore_orphan_reconciliation_operations(operation_id,token,zone,storage_object,size_bytes,modified_at,actor_id,correlation_id,status,reason_code,authorized_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'authorized',$9,$10) ON CONFLICT(token) DO NOTHING`, operation.OperationID, operation.Token, operation.Zone, operation.StorageObject, operation.Size, operation.ModifiedAt, operation.ActorID, operation.CorrelationID, operation.ReasonCode, operation.AuthorizedAt)
	if err != nil {
		return OrphanReconciliationOperation{}, false, err
	}
	created := command.RowsAffected() == 1
	if created {
		if err := auditoutbox.Enqueue(ctx, tx, intent); err != nil {
			return OrphanReconciliationOperation{}, false, err
		}
	} else {
		if err := tx.QueryRow(ctx, `SELECT operation_id,token,zone,storage_object,size_bytes,modified_at,actor_id,correlation_id,status,reason_code,authorized_at,completed_at FROM securestore_orphan_reconciliation_operations WHERE token=$1`, operation.Token).Scan(&operation.OperationID, &operation.Token, &operation.Zone, &operation.StorageObject, &operation.Size, &operation.ModifiedAt, &operation.ActorID, &operation.CorrelationID, &operation.Status, &operation.ReasonCode, &operation.AuthorizedAt, &operation.CompletedAt); err != nil {
			return OrphanReconciliationOperation{}, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return OrphanReconciliationOperation{}, false, err
	}
	return operation, created, nil
}

func (r *PostgresRepository) CompleteOrphanReconciliation(operationID, status, reasonCode string, completedAt time.Time, intent auditoutbox.Intent) (bool, error) {
	ctx := context.Background()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, `UPDATE securestore_orphan_reconciliation_operations SET status=$1,reason_code=$2,completed_at=$3 WHERE operation_id=$4 AND status='authorized'`, status, reasonCode, completedAt, operationID)
	if err != nil {
		return false, err
	}
	updated := command.RowsAffected() == 1
	if updated {
		if err := auditoutbox.Enqueue(ctx, tx, intent); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return updated, nil
}

func (r *PostgresRepository) PendingOrphanReconciliations(limit int) ([]OrphanReconciliationOperation, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT operation_id,token,zone,storage_object,size_bytes,modified_at,actor_id,correlation_id,status,reason_code,authorized_at,completed_at FROM securestore_orphan_reconciliation_operations WHERE status='authorized' ORDER BY authorized_at,operation_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []OrphanReconciliationOperation{}
	for rows.Next() {
		var operation OrphanReconciliationOperation
		if err := rows.Scan(&operation.OperationID, &operation.Token, &operation.Zone, &operation.StorageObject, &operation.Size, &operation.ModifiedAt, &operation.ActorID, &operation.CorrelationID, &operation.Status, &operation.ReasonCode, &operation.AuthorizedAt, &operation.CompletedAt); err != nil {
			return nil, err
		}
		result = append(result, operation)
	}
	return result, rows.Err()
}

var _ orphanReconciliationRepository = (*PostgresRepository)(nil)

func (r *PostgresRepository) Close() { r.pool.Close() }

func (r *PostgresRepository) ProtectedBlobObjects() ([]string, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT blob_object FROM securestore_protected_versions WHERE wrapped_dek IS NOT NULL ORDER BY blob_object`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	objects := []string{}
	for rows.Next() {
		var object string
		if err := rows.Scan(&object); err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	return objects, rows.Err()
}

func (r *PostgresRepository) ProtectedBlobObjectExists(object string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM securestore_protected_versions WHERE blob_object=$1 AND wrapped_dek IS NOT NULL)`, object).Scan(&exists)
	return exists, err
}

var _ capacityRepository = (*PostgresRepository)(nil)

func (*PostgresRepository) Durable() bool { return true }

func (r *PostgresRepository) Create(value Metadata) (Metadata, bool, error) {
	_, err := r.pool.Exec(context.Background(), `INSERT INTO securestore_protected_versions
		(version_id,operation_id,owner_id,blob_object,schema_version,algorithm,kek_id,kek_version,wrapping_kek_id,wrapping_kek_version,wrapped_dek,nonce,plaintext_size,plaintext_digest,media_type,inspection_record_id,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		value.VersionID, value.UploadID, value.OwnerID, value.BlobObject, value.SchemaVersion,
		value.Algorithm, value.KEKID, value.KEKVersion, value.WrappingKEKID, value.WrappingKEKVersion, value.WrappedDEK, value.Nonce,
		value.PlaintextSize, value.PlaintextDigest, value.MediaType, value.InspectionRecordID, value.CreatedAt)
	if err == nil {
		return value, false, nil
	}
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "23505" {
		return Metadata{}, false, err
	}
	existing, findErr := r.FindByUpload(value.OwnerID, value.UploadID)
	return existing, true, findErr
}

func (r *PostgresRepository) FindByUpload(ownerID, uploadID string) (Metadata, error) {
	var value Metadata
	err := r.pool.QueryRow(context.Background(), `SELECT operation_id,version_id,owner_id,blob_object,schema_version,algorithm,kek_id,kek_version,wrapping_kek_id,wrapping_kek_version,wrapped_dek,nonce,plaintext_size,plaintext_digest,media_type,inspection_record_id,created_at FROM securestore_protected_versions WHERE operation_id=$1 AND owner_id=$2`, uploadID, ownerID).Scan(
		&value.UploadID, &value.VersionID, &value.OwnerID, &value.BlobObject, &value.SchemaVersion,
		&value.Algorithm, &value.KEKID, &value.KEKVersion, &value.WrappingKEKID, &value.WrappingKEKVersion, &value.WrappedDEK, &value.Nonce,
		&value.PlaintextSize, &value.PlaintextDigest, &value.MediaType, &value.InspectionRecordID, &value.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Metadata{}, ErrNotFound
	}
	return value, err
}

var _ Repository = (*PostgresRepository)(nil)

func (r *PostgresRepository) KeyRotationPosture(currentID, currentVersion string) (KeyRotationPosture, error) {
	result := KeyRotationPosture{CurrentKEKID: currentID, CurrentKEKVersion: currentVersion, Durable: true}
	err := r.pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE wrapped_dek IS NOT NULL),count(*) FILTER (WHERE wrapped_dek IS NOT NULL AND wrapping_kek_id=$1 AND wrapping_kek_version=$2),count(*) FILTER (WHERE wrapped_dek IS NOT NULL AND (wrapping_kek_id<>$1 OR wrapping_kek_version<>$2)) FROM securestore_protected_versions`, currentID, currentVersion).Scan(&result.ProtectedVersions, &result.CurrentVersions, &result.PendingVersions)
	if err != nil {
		return KeyRotationPosture{}, err
	}
	err = r.pool.QueryRow(context.Background(), `SELECT count(*) FROM securestore_dek_rewrap_operations WHERE status='completed'`).Scan(&result.CompletedRewraps)
	return result, err
}

func (r *PostgresRepository) ListDEKRewrapCandidates(currentID, currentVersion string, limit int) ([]Metadata, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT operation_id,version_id,owner_id,blob_object,schema_version,algorithm,kek_id,kek_version,wrapping_kek_id,wrapping_kek_version,wrapped_dek,nonce,plaintext_size,plaintext_digest,media_type,inspection_record_id,created_at FROM securestore_protected_versions WHERE wrapped_dek IS NOT NULL AND (wrapping_kek_id<>$1 OR wrapping_kek_version<>$2) ORDER BY created_at,version_id LIMIT $3`, currentID, currentVersion, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Metadata{}
	for rows.Next() {
		var value Metadata
		if err := rows.Scan(&value.UploadID, &value.VersionID, &value.OwnerID, &value.BlobObject, &value.SchemaVersion, &value.Algorithm, &value.KEKID, &value.KEKVersion, &value.WrappingKEKID, &value.WrappingKEKVersion, &value.WrappedDEK, &value.Nonce, &value.PlaintextSize, &value.PlaintextDigest, &value.MediaType, &value.InspectionRecordID, &value.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (r *PostgresRepository) CommitDEKRewrap(candidate Metadata, replacement []byte, targetID, targetVersion, operationID string, attemptedAt time.Time, intent auditoutbox.Intent) (bool, error) {
	ctx := context.Background()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fromID, fromVersion := wrappingKeyIdentity(candidate)
	command, err := tx.Exec(ctx, `UPDATE securestore_protected_versions SET wrapped_dek=$1,wrapping_kek_id=$2,wrapping_kek_version=$3 WHERE version_id=$4 AND wrapped_dek=$5 AND wrapping_kek_id=$6 AND wrapping_kek_version=$7`, replacement, targetID, targetVersion, candidate.VersionID, candidate.WrappedDEK, fromID, fromVersion)
	if err != nil {
		return false, err
	}
	if command.RowsAffected() == 0 {
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		return false, nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO securestore_dek_rewrap_operations(operation_id,version_id,from_kek_id,from_kek_version,to_kek_id,to_kek_version,status,reason_code,attempted_at,completed_at) VALUES($1,$2,$3,$4,$5,$6,'completed','administrator_rotation',$7,$7) ON CONFLICT(version_id,to_kek_id,to_kek_version) DO UPDATE SET status='completed',reason_code='administrator_rotation',attempted_at=EXCLUDED.attempted_at,completed_at=EXCLUDED.completed_at`, operationID, candidate.VersionID, fromID, fromVersion, targetID, targetVersion, attemptedAt); err != nil {
		return false, err
	}
	if err := auditoutbox.Enqueue(ctx, tx, intent); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

var _ rewrapRepository = (*PostgresRepository)(nil)

func (r *PostgresRepository) RegisterInitial(ownerID, name string, metadata Metadata) (LogicalFile, Version, error) {
	ctx := context.Background()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return LogicalFile{}, Version{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var existingFileID string
	err = tx.QueryRow(ctx, `SELECT file_id FROM securestore_files WHERE owner_id=$1 AND current_version_id=$2`, ownerID, metadata.VersionID).Scan(&existingFileID)
	if err == nil {
		_ = tx.Rollback(ctx)
		details, findErr := r.Details(ownerID, existingFileID)
		if findErr != nil {
			return LogicalFile{}, Version{}, findErr
		}
		return details.File, details.Versions[0], nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return LogicalFile{}, Version{}, err
	}
	fileID, err := opaqueID("file")
	if err != nil {
		return LogicalFile{}, Version{}, err
	}
	file := LogicalFile{FileID: fileID, OwnerID: ownerID, Name: name, CurrentVersionID: metadata.VersionID, CreatedAt: metadata.CreatedAt, UpdatedAt: metadata.CreatedAt}
	version := Version{FileID: fileID, VersionID: metadata.VersionID, OperationID: metadata.UploadID, Number: 1, PlaintextSize: metadata.PlaintextSize, MediaType: metadata.MediaType, Reason: "initial_upload", Current: true, CreatedAt: metadata.CreatedAt}
	if _, err = tx.Exec(ctx, `INSERT INTO securestore_files(file_id,owner_id,name,current_version_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5)`, file.FileID, file.OwnerID, file.Name, file.CurrentVersionID, file.CreatedAt); err != nil {
		return LogicalFile{}, Version{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO securestore_file_versions(file_id,version_id,operation_id,version_number,plaintext_size,media_type,reason,created_at) VALUES($1,$2,$3,1,$4,$5,$6,$7)`, fileID, metadata.VersionID, metadata.UploadID, metadata.PlaintextSize, metadata.MediaType, version.Reason, metadata.CreatedAt); err != nil {
		return LogicalFile{}, Version{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return LogicalFile{}, Version{}, err
	}
	return file, version, nil
}

func (r *PostgresRepository) ListFiles(ownerID string) ([]LogicalFile, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT f.file_id,f.owner_id,f.name,f.current_version_id,f.created_at,f.updated_at FROM securestore_files f WHERE f.owner_id=$1 AND f.deleted_at IS NULL AND f.purged_at IS NULL AND EXISTS(SELECT 1 FROM securestore_file_versions v WHERE v.file_id=f.file_id) ORDER BY f.updated_at DESC,f.file_id`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []LogicalFile{}
	for rows.Next() {
		var f LogicalFile
		if err := rows.Scan(&f.FileID, &f.OwnerID, &f.Name, &f.CurrentVersionID, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

func (r *PostgresRepository) Details(ownerID, fileID string) (Details, error) {
	var d Details
	err := r.pool.QueryRow(context.Background(), `SELECT file_id,owner_id,name,current_version_id,created_at,updated_at FROM securestore_files WHERE file_id=$1 AND owner_id=$2 AND deleted_at IS NULL AND purged_at IS NULL`, fileID, ownerID).Scan(&d.File.FileID, &d.File.OwnerID, &d.File.Name, &d.File.CurrentVersionID, &d.File.CreatedAt, &d.File.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Details{}, ErrNotFound
	}
	if err != nil {
		return Details{}, err
	}
	d.Access = "owner"
	rows, err := r.pool.Query(context.Background(), `SELECT file_id,version_id,COALESCE(source_version_id,''),operation_id,version_number,plaintext_size,media_type,reason,(version_id=$2),created_at FROM securestore_file_versions WHERE file_id=$1 ORDER BY version_number DESC`, fileID, d.File.CurrentVersionID)
	if err != nil {
		return Details{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var v Version
		if err := rows.Scan(&v.FileID, &v.VersionID, &v.SourceVersionID, &v.OperationID, &v.Number, &v.PlaintextSize, &v.MediaType, &v.Reason, &v.Current, &v.CreatedAt); err != nil {
			return Details{}, err
		}
		d.Versions = append(d.Versions, v)
	}
	return d, rows.Err()
}

func (r *PostgresRepository) FindVersion(ownerID, fileID, versionID string) (Metadata, error) {
	var value Metadata
	err := r.pool.QueryRow(context.Background(), `SELECT p.operation_id,p.version_id,p.owner_id,p.blob_object,p.schema_version,p.algorithm,p.kek_id,p.kek_version,p.wrapping_kek_id,p.wrapping_kek_version,p.wrapped_dek,p.nonce,p.plaintext_size,p.plaintext_digest,p.media_type,p.inspection_record_id,p.created_at FROM securestore_file_versions v JOIN securestore_files f ON f.file_id=v.file_id JOIN securestore_protected_versions p ON p.version_id=v.version_id WHERE f.file_id=$1 AND f.owner_id=$2 AND f.deleted_at IS NULL AND f.purged_at IS NULL AND v.version_id=$3`, fileID, ownerID, versionID).Scan(&value.UploadID, &value.VersionID, &value.OwnerID, &value.BlobObject, &value.SchemaVersion, &value.Algorithm, &value.KEKID, &value.KEKVersion, &value.WrappingKEKID, &value.WrappingKEKVersion, &value.WrappedDEK, &value.Nonce, &value.PlaintextSize, &value.PlaintextDigest, &value.MediaType, &value.InspectionRecordID, &value.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Metadata{}, ErrNotFound
	}
	return value, err
}

func (r *PostgresRepository) CommitRestore(ownerID, fileID, sourceVersionID string, metadata Metadata) (Version, error) {
	return r.commitRestore(ownerID, fileID, sourceVersionID, metadata, nil)
}

func (r *PostgresRepository) CommitRestoreAudited(ownerID, fileID, sourceVersionID string, metadata Metadata, intent auditoutbox.Intent) (Version, error) {
	return r.commitRestore(ownerID, fileID, sourceVersionID, metadata, &intent)
}

func (r *PostgresRepository) commitRestore(ownerID, fileID, sourceVersionID string, metadata Metadata, intent *auditoutbox.Intent) (Version, error) {
	ctx := context.Background()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var existing Version
	err = tx.QueryRow(ctx, `SELECT v.file_id,v.version_id,COALESCE(v.source_version_id,''),v.operation_id,v.version_number,v.plaintext_size,v.media_type,v.reason,(v.version_id=f.current_version_id),v.created_at FROM securestore_file_versions v JOIN securestore_files f ON f.file_id=v.file_id WHERE f.owner_id=$1 AND v.file_id=$2 AND v.operation_id=$3`, ownerID, fileID, metadata.UploadID).Scan(&existing.FileID, &existing.VersionID, &existing.SourceVersionID, &existing.OperationID, &existing.Number, &existing.PlaintextSize, &existing.MediaType, &existing.Reason, &existing.Current, &existing.CreatedAt)
	if err == nil {
		if existing.SourceVersionID != sourceVersionID {
			return Version{}, errors.New("restore idempotency conflict")
		}
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Version{}, err
	}

	// The row lock serializes version numbering and current-pointer changes for
	// this logical file. Source membership is checked inside the same transaction.
	var current string
	err = tx.QueryRow(ctx, `SELECT current_version_id FROM securestore_files WHERE file_id=$1 AND owner_id=$2 AND deleted_at IS NULL AND purged_at IS NULL FOR UPDATE`, fileID, ownerID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, err
	}
	var sourceExists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM securestore_file_versions WHERE file_id=$1 AND version_id=$2)`, fileID, sourceVersionID).Scan(&sourceExists); err != nil {
		return Version{}, err
	}
	if !sourceExists {
		return Version{}, ErrNotFound
	}
	var maxNumber int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(max(version_number),0) FROM securestore_file_versions WHERE file_id=$1`, fileID).Scan(&maxNumber); err != nil {
		return Version{}, err
	}
	v := Version{FileID: fileID, VersionID: metadata.VersionID, SourceVersionID: sourceVersionID, OperationID: metadata.UploadID, Number: maxNumber + 1, PlaintextSize: metadata.PlaintextSize, MediaType: metadata.MediaType, Reason: "verified_restore", Current: true, CreatedAt: metadata.CreatedAt}
	if _, err = tx.Exec(ctx, `INSERT INTO securestore_file_versions(file_id,version_id,source_version_id,operation_id,version_number,plaintext_size,media_type,reason,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, v.FileID, v.VersionID, v.SourceVersionID, v.OperationID, v.Number, v.PlaintextSize, v.MediaType, v.Reason, v.CreatedAt); err != nil {
		return Version{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE securestore_files SET current_version_id=$2,updated_at=$3 WHERE file_id=$1`, fileID, metadata.VersionID, metadata.CreatedAt); err != nil {
		return Version{}, err
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return Version{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return Version{}, err
	}
	return v, nil
}

var _ CatalogRepository = (*PostgresRepository)(nil)

func (r *PostgresRepository) CreateGrant(ownerID, fileID string, recipient Recipient, permission string, expiresAt *time.Time) (Grant, error) {
	return r.createGrant(ownerID, fileID, recipient, permission, expiresAt, nil)
}

func (r *PostgresRepository) CreateGrantAudited(ownerID, fileID string, recipient Recipient, permission string, expiresAt *time.Time, intent auditoutbox.Intent) (Grant, error) {
	return r.createGrant(ownerID, fileID, recipient, permission, expiresAt, &intent)
}

func (r *PostgresRepository) createGrant(ownerID, fileID string, recipient Recipient, permission string, expiresAt *time.Time, intent *auditoutbox.Intent) (Grant, error) {
	grantID, err := opaqueID("grant")
	if err != nil {
		return Grant{}, err
	}
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Grant{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	createdAt := time.Now().UTC()
	var grant Grant
	err = tx.QueryRow(ctx, `
		INSERT INTO securestore_file_access_grants(grant_id,file_id,owner_id,recipient_id,permission,expires_at,created_at)
		SELECT $1,f.file_id,f.owner_id,u.id,$5,$6,$7
		FROM securestore_files f JOIN securestore_users u ON u.id=$4
		WHERE f.file_id=$2 AND f.owner_id=$3 AND f.deleted_at IS NULL AND f.purged_at IS NULL AND u.role='user' AND u.account_status='active' AND u.email_verified_at IS NOT NULL AND u.id<>f.owner_id
		ON CONFLICT(file_id,recipient_id) WHERE revoked_at IS NULL
		DO UPDATE SET permission=EXCLUDED.permission,expires_at=EXCLUDED.expires_at,created_at=EXCLUDED.created_at
		RETURNING grant_id,file_id,owner_id,recipient_id,permission,expires_at,created_at,revoked_at`,
		grantID, fileID, ownerID, recipient.ID, permission, expiresAt, createdAt).Scan(&grant.GrantID, &grant.FileID, &grant.OwnerID, &grant.RecipientID, &grant.Permission, &grant.ExpiresAt, &grant.CreatedAt, &grant.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, err
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return Grant{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Grant{}, err
	}
	grant.RecipientName, grant.RecipientEmail = recipient.Name, recipient.Email
	return grant, nil
}

func (r *PostgresRepository) ListGrants(ownerID, fileID string) ([]Grant, error) {
	var owns bool
	if err := r.pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM securestore_files WHERE file_id=$1 AND owner_id=$2)`, fileID, ownerID).Scan(&owns); err != nil {
		return nil, err
	}
	if !owns {
		return nil, ErrNotFound
	}
	rows, err := r.pool.Query(context.Background(), `SELECT g.grant_id,g.file_id,g.owner_id,g.recipient_id,u.name,u.email,g.permission,g.expires_at,g.created_at,g.revoked_at FROM securestore_file_access_grants g JOIN securestore_users u ON u.id=g.recipient_id WHERE g.file_id=$1 AND g.owner_id=$2 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>now()) ORDER BY g.created_at DESC,g.grant_id`, fileID, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := []Grant{}
	for rows.Next() {
		var grant Grant
		if err := rows.Scan(&grant.GrantID, &grant.FileID, &grant.OwnerID, &grant.RecipientID, &grant.RecipientName, &grant.RecipientEmail, &grant.Permission, &grant.ExpiresAt, &grant.CreatedAt, &grant.RevokedAt); err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (r *PostgresRepository) RevokeGrant(ownerID, fileID, grantID string) error {
	return r.revokeGrant(ownerID, fileID, grantID, nil)
}

func (r *PostgresRepository) RevokeGrantAudited(ownerID, fileID, grantID string, intent auditoutbox.Intent) error {
	return r.revokeGrant(ownerID, fileID, grantID, &intent)
}

func (r *PostgresRepository) revokeGrant(ownerID, fileID, grantID string, intent *auditoutbox.Intent) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `UPDATE securestore_file_access_grants SET revoked_at=now() WHERE grant_id=$1 AND file_id=$2 AND owner_id=$3 AND revoked_at IS NULL`, grantID, fileID, ownerID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrNotFound
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) AuthorizedDetails(requesterID, fileID, capability string) (Details, error) {
	var d Details
	err := r.pool.QueryRow(context.Background(), `SELECT f.file_id,f.owner_id,f.name,f.current_version_id,f.created_at,f.updated_at FROM securestore_files f WHERE f.file_id=$2 AND f.deleted_at IS NULL AND f.purged_at IS NULL AND (f.owner_id=$1 OR EXISTS(SELECT 1 FROM securestore_file_access_grants g WHERE g.file_id=f.file_id AND g.recipient_id=$1 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>now()) AND ($3='read' OR g.permission='download')))`, requesterID, fileID, capability).Scan(&d.File.FileID, &d.File.OwnerID, &d.File.Name, &d.File.CurrentVersionID, &d.File.CreatedAt, &d.File.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Details{}, ErrNotFound
	}
	if err != nil {
		return Details{}, err
	}
	if d.File.OwnerID == requesterID {
		d.Access = "owner"
	} else if err := r.pool.QueryRow(context.Background(), `SELECT permission FROM securestore_file_access_grants WHERE file_id=$1 AND recipient_id=$2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`, fileID, requesterID).Scan(&d.Access); err != nil {
		return Details{}, ErrNotFound
	}
	rows, err := r.pool.Query(context.Background(), `SELECT file_id,version_id,COALESCE(source_version_id,''),operation_id,version_number,plaintext_size,media_type,reason,(version_id=$2),created_at FROM securestore_file_versions WHERE file_id=$1 ORDER BY version_number DESC`, fileID, d.File.CurrentVersionID)
	if err != nil {
		return Details{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var v Version
		if err := rows.Scan(&v.FileID, &v.VersionID, &v.SourceVersionID, &v.OperationID, &v.Number, &v.PlaintextSize, &v.MediaType, &v.Reason, &v.Current, &v.CreatedAt); err != nil {
			return Details{}, err
		}
		d.Versions = append(d.Versions, v)
	}
	return d, rows.Err()
}

func (r *PostgresRepository) AuthorizedCurrentMetadata(requesterID, fileID, capability string) (Metadata, error) {
	var value Metadata
	err := r.pool.QueryRow(context.Background(), `SELECT p.operation_id,p.version_id,p.owner_id,p.blob_object,p.schema_version,p.algorithm,p.kek_id,p.kek_version,p.wrapping_kek_id,p.wrapping_kek_version,p.wrapped_dek,p.nonce,p.plaintext_size,p.plaintext_digest,p.media_type,p.inspection_record_id,p.created_at FROM securestore_files f JOIN securestore_protected_versions p ON p.version_id=f.current_version_id WHERE f.file_id=$2 AND f.deleted_at IS NULL AND f.purged_at IS NULL AND (f.owner_id=$1 OR EXISTS(SELECT 1 FROM securestore_file_access_grants g WHERE g.file_id=f.file_id AND g.recipient_id=$1 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>now()) AND ($3='read' OR g.permission='download')))`, requesterID, fileID, capability).Scan(&value.UploadID, &value.VersionID, &value.OwnerID, &value.BlobObject, &value.SchemaVersion, &value.Algorithm, &value.KEKID, &value.KEKVersion, &value.WrappingKEKID, &value.WrappingKEKVersion, &value.WrappedDEK, &value.Nonce, &value.PlaintextSize, &value.PlaintextDigest, &value.MediaType, &value.InspectionRecordID, &value.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Metadata{}, ErrNotFound
	}
	return value, err
}

func (r *PostgresRepository) ListSharedFiles(recipientID string) ([]SharedFile, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT f.file_id,f.owner_id,f.name,f.current_version_id,f.created_at,f.updated_at,u.name,u.email,g.permission FROM securestore_file_access_grants g JOIN securestore_files f ON f.file_id=g.file_id JOIN securestore_users u ON u.id=f.owner_id WHERE g.recipient_id=$1 AND f.deleted_at IS NULL AND f.purged_at IS NULL AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>now()) ORDER BY f.updated_at DESC,f.file_id`, recipientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	files := []SharedFile{}
	for rows.Next() {
		var file SharedFile
		if err := rows.Scan(&file.FileID, &file.OwnerID, &file.Name, &file.CurrentVersionID, &file.CreatedAt, &file.UpdatedAt, &file.OwnerName, &file.OwnerEmail, &file.Permission); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, rows.Err()
}

var _ AccessRepository = (*PostgresRepository)(nil)

func (r *PostgresRepository) ListTrash(ownerID string) ([]LifecycleFile, error) {
	rows, err := r.pool.Query(context.Background(), lifecycleSelect+` WHERE owner_id=$1 AND deleted_at IS NOT NULL AND purged_at IS NULL ORDER BY deleted_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []LifecycleFile{}
	for rows.Next() {
		file, err := scanLifecycleFileValue(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, file)
	}
	return result, rows.Err()
}

func (r *PostgresRepository) MoveToTrash(ownerID, fileID string, now, purgeAfter time.Time) (LifecycleFile, error) {
	return r.moveToTrash(ownerID, fileID, now, purgeAfter, nil)
}

func (r *PostgresRepository) MoveToTrashAudited(ownerID, fileID string, now, purgeAfter time.Time, intent auditoutbox.Intent) (LifecycleFile, error) {
	return r.moveToTrash(ownerID, fileID, now, purgeAfter, &intent)
}

func (r *PostgresRepository) moveToTrash(ownerID, fileID string, now, purgeAfter time.Time, intent *auditoutbox.Intent) (LifecycleFile, error) {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return LifecycleFile{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var file LifecycleFile
	err = scanLifecycleFile(tx.QueryRow(ctx, lifecycleSelect+` WHERE file_id=$1 AND owner_id=$2 AND purged_at IS NULL AND (retention_until IS NULL OR retention_until<=$3) AND legal_hold=false FOR UPDATE`, fileID, ownerID, now), &file)
	if errors.Is(err, pgx.ErrNoRows) {
		var retained, held bool
		check := tx.QueryRow(ctx, `SELECT COALESCE(retention_until>$3,false),legal_hold FROM securestore_files WHERE file_id=$1 AND owner_id=$2 AND purged_at IS NULL`, fileID, ownerID, now).Scan(&retained, &held)
		if errors.Is(check, pgx.ErrNoRows) {
			return LifecycleFile{}, ErrNotFound
		}
		if check != nil {
			return LifecycleFile{}, check
		}
		if held {
			return LifecycleFile{}, ErrLegalHold
		}
		if retained {
			return LifecycleFile{}, ErrRetentionActive
		}
		return LifecycleFile{}, ErrNotFound
	}
	if err != nil {
		return LifecycleFile{}, err
	}
	if file.DeletedAt != nil {
		if err := tx.Commit(ctx); err != nil {
			return LifecycleFile{}, err
		}
		return file, nil
	}
	_, err = tx.Exec(ctx, `UPDATE securestore_files SET deleted_at=$3,purge_after=$4,updated_at=$3 WHERE file_id=$1 AND owner_id=$2`, fileID, ownerID, now, purgeAfter)
	if err != nil {
		return LifecycleFile{}, err
	}
	// Trash is also a grant-revocation boundary. Restoration never silently
	// reactivates access that the owner may no longer expect to exist.
	if _, err = tx.Exec(ctx, `UPDATE securestore_file_access_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE file_id=$1`, fileID, now); err != nil {
		return LifecycleFile{}, err
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return LifecycleFile{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return LifecycleFile{}, err
	}
	file.DeletedAt, file.PurgeAfter, file.UpdatedAt = &now, &purgeAfter, now
	return file, nil
}

func (r *PostgresRepository) RestoreFromTrash(ownerID, fileID string, now time.Time) (LifecycleFile, error) {
	return r.restoreFromTrash(ownerID, fileID, now, nil)
}

func (r *PostgresRepository) RestoreFromTrashAudited(ownerID, fileID string, now time.Time, intent auditoutbox.Intent) (LifecycleFile, error) {
	return r.restoreFromTrash(ownerID, fileID, now, &intent)
}

func (r *PostgresRepository) restoreFromTrash(ownerID, fileID string, now time.Time, intent *auditoutbox.Intent) (LifecycleFile, error) {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return LifecycleFile{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var file LifecycleFile
	err = scanLifecycleFile(tx.QueryRow(ctx, lifecycleSelect+` WHERE file_id=$1 AND owner_id=$2 AND deleted_at IS NOT NULL AND purged_at IS NULL FOR UPDATE`, fileID, ownerID), &file)
	if errors.Is(err, pgx.ErrNoRows) {
		return LifecycleFile{}, ErrNotInTrash
	}
	if err != nil {
		return LifecycleFile{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE securestore_files SET deleted_at=NULL,purge_after=NULL,updated_at=$3 WHERE file_id=$1 AND owner_id=$2`, fileID, ownerID, now)
	if err != nil {
		return LifecycleFile{}, err
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return LifecycleFile{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return LifecycleFile{}, err
	}
	file.DeletedAt, file.PurgeAfter, file.UpdatedAt = nil, nil, now
	return file, nil
}

func (r *PostgresRepository) Purge(ownerID, fileID, operationID string, now time.Time) (PurgeResult, error) {
	return r.purge(ownerID, fileID, operationID, now, nil)
}

func (r *PostgresRepository) PurgeAudited(ownerID, fileID, operationID string, now time.Time, intent auditoutbox.Intent) (PurgeResult, error) {
	return r.purge(ownerID, fileID, operationID, now, &intent)
}

func (r *PostgresRepository) purge(ownerID, fileID, operationID string, now time.Time, intent *auditoutbox.Intent) (PurgeResult, error) {
	ctx := context.Background()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PurgeResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var existing PurgeResult
	var existingStatus string
	var existingCompleted *time.Time
	err = tx.QueryRow(ctx, `SELECT file_id,operation_id,status,destroyed_keys,completed_at FROM securestore_deletion_operations WHERE operation_id=$1 AND owner_id=$2`, operationID, ownerID).Scan(&existing.FileID, &existing.OperationID, &existingStatus, &existing.DestroyedKeys, &existingCompleted)
	if err == nil {
		if existing.FileID != fileID {
			return PurgeResult{}, errors.New("purge idempotency conflict")
		}
		if existingStatus == "completed" && existingCompleted != nil {
			existing.CompletedAt = *existingCompleted
			return existing, nil
		}
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PurgeResult{}, err
	}
	var purgeAfter *time.Time
	var retention *time.Time
	var hold bool
	err = tx.QueryRow(ctx, `SELECT purge_after,retention_until,legal_hold FROM securestore_files WHERE file_id=$1 AND owner_id=$2 AND deleted_at IS NOT NULL AND purged_at IS NULL FOR UPDATE`, fileID, ownerID).Scan(&purgeAfter, &retention, &hold)
	if errors.Is(err, pgx.ErrNoRows) {
		return PurgeResult{}, ErrNotInTrash
	}
	if err != nil {
		return PurgeResult{}, err
	}
	if hold {
		return PurgeResult{}, ErrLegalHold
	}
	if retention != nil && retention.After(now) {
		return PurgeResult{}, ErrRetentionActive
	}
	if purgeAfter == nil || purgeAfter.After(now) {
		return PurgeResult{}, ErrPurgeTooEarly
	}
	rows, err := tx.Query(ctx, `SELECT p.blob_object FROM securestore_file_versions v JOIN securestore_protected_versions p ON p.version_id=v.version_id WHERE v.file_id=$1 AND p.wrapped_dek IS NOT NULL`, fileID)
	if err != nil {
		return PurgeResult{}, err
	}
	objects := []string{}
	for rows.Next() {
		var object string
		if err := rows.Scan(&object); err != nil {
			rows.Close()
			return PurgeResult{}, err
		}
		objects = append(objects, object)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return PurgeResult{}, err
	}
	result := PurgeResult{FileID: fileID, OperationID: operationID, DestroyedKeys: len(objects), CompletedAt: now, BlobObjects: objects}
	if _, err = tx.Exec(ctx, `UPDATE securestore_protected_versions p SET wrapped_dek=NULL FROM securestore_file_versions v WHERE v.file_id=$1 AND p.version_id=v.version_id`, fileID); err != nil {
		return PurgeResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE securestore_file_access_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE file_id=$1`, fileID, now); err != nil {
		return PurgeResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE securestore_files SET purged_at=$2,updated_at=$2 WHERE file_id=$1`, fileID, now); err != nil {
		return PurgeResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO securestore_deletion_operations(operation_id,file_id,owner_id,status,destroyed_keys,attempts,reason_code,updated_at,completed_at) VALUES($1,$2,$3,'completed',$4,1,'',$5,$5) ON CONFLICT(operation_id) DO UPDATE SET status='completed',destroyed_keys=EXCLUDED.destroyed_keys,attempts=securestore_deletion_operations.attempts+1,reason_code='',updated_at=EXCLUDED.updated_at,completed_at=EXCLUDED.completed_at`, operationID, fileID, ownerID, result.DestroyedKeys, now); err != nil {
		return PurgeResult{}, err
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return PurgeResult{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return PurgeResult{}, err
	}
	return result, nil
}

func (r *PostgresRepository) SetRetention(fileID string, until *time.Time) (LifecycleFile, error) {
	return r.setRetention(fileID, until, nil)
}

func (r *PostgresRepository) SetRetentionAudited(fileID string, until *time.Time, intent auditoutbox.Intent) (LifecycleFile, error) {
	return r.setRetention(fileID, until, &intent)
}

func (r *PostgresRepository) setRetention(fileID string, until *time.Time, intent *auditoutbox.Intent) (LifecycleFile, error) {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return LifecycleFile{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var file LifecycleFile
	err = scanLifecycleFile(tx.QueryRow(ctx, lifecycleSelect+` WHERE file_id=$1 AND purged_at IS NULL FOR UPDATE`, fileID), &file)
	if errors.Is(err, pgx.ErrNoRows) {
		return LifecycleFile{}, ErrNotFound
	}
	if err != nil {
		return LifecycleFile{}, err
	}
	if file.RetentionUntil != nil && (until == nil || until.Before(*file.RetentionUntil)) {
		return LifecycleFile{}, ErrRetentionActive
	}
	_, err = tx.Exec(ctx, `UPDATE securestore_files SET retention_until=$2 WHERE file_id=$1`, fileID, until)
	if err != nil {
		return LifecycleFile{}, err
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return LifecycleFile{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return LifecycleFile{}, err
	}
	file.RetentionUntil = until
	return file, nil
}
func (r *PostgresRepository) SetLegalHold(fileID string, enabled bool, reason string) (LifecycleFile, error) {
	return r.setLegalHold(fileID, enabled, reason, nil)
}

func (r *PostgresRepository) SetLegalHoldAudited(fileID string, enabled bool, reason string, intent auditoutbox.Intent) (LifecycleFile, error) {
	return r.setLegalHold(fileID, enabled, reason, &intent)
}

func (r *PostgresRepository) setLegalHold(fileID string, enabled bool, reason string, intent *auditoutbox.Intent) (LifecycleFile, error) {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return LifecycleFile{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var file LifecycleFile
	err = scanLifecycleFile(tx.QueryRow(ctx, lifecycleSelect+` WHERE file_id=$1 AND purged_at IS NULL FOR UPDATE`, fileID), &file)
	if errors.Is(err, pgx.ErrNoRows) {
		return LifecycleFile{}, ErrNotFound
	}
	if err != nil {
		return LifecycleFile{}, err
	}
	if !enabled {
		reason = ""
	}
	_, err = tx.Exec(ctx, `UPDATE securestore_files SET legal_hold=$2,legal_hold_reason=$3 WHERE file_id=$1`, fileID, enabled, reason)
	if err != nil {
		return LifecycleFile{}, err
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return LifecycleFile{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return LifecycleFile{}, err
	}
	file.LegalHold, file.LegalHoldReason = enabled, reason
	return file, nil
}
func (r *PostgresRepository) LifecycleSummary(now time.Time, limit int) (LifecycleSummary, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	var summary LifecycleSummary
	err := r.pool.QueryRow(context.Background(), `SELECT count(*) FILTER(WHERE deleted_at IS NULL AND purged_at IS NULL),count(*) FILTER(WHERE deleted_at IS NOT NULL AND purged_at IS NULL),count(*) FILTER(WHERE retention_until> $1 AND purged_at IS NULL),count(*) FILTER(WHERE legal_hold AND purged_at IS NULL),count(*) FILTER(WHERE purged_at IS NOT NULL),count(*) FILTER(WHERE purge_after<=$1 AND purged_at IS NULL AND NOT legal_hold AND (retention_until IS NULL OR retention_until<=$1)) FROM securestore_files`, now).Scan(&summary.Active, &summary.Trashed, &summary.Retained, &summary.Held, &summary.Purged, &summary.EligibleForPurge)
	if err != nil {
		return LifecycleSummary{}, err
	}
	rows, err := r.pool.Query(context.Background(), lifecycleSelect+` ORDER BY updated_at DESC LIMIT $1`, limit)
	if err != nil {
		return LifecycleSummary{}, err
	}
	defer rows.Close()
	for rows.Next() {
		file, err := scanLifecycleFileValue(rows)
		if err != nil {
			return LifecycleSummary{}, err
		}
		summary.Files = append(summary.Files, file)
	}
	if err := rows.Err(); err != nil {
		return LifecycleSummary{}, err
	}
	operationRows, err := r.pool.Query(context.Background(), `SELECT operation_id,file_id,owner_id,status,destroyed_keys,attempts,reason_code,updated_at,completed_at FROM securestore_deletion_operations ORDER BY updated_at DESC LIMIT $1`, limit)
	if err != nil {
		return LifecycleSummary{}, err
	}
	defer operationRows.Close()
	for operationRows.Next() {
		var operation DeletionOperation
		if err := operationRows.Scan(&operation.OperationID, &operation.FileID, &operation.OwnerID, &operation.Status, &operation.DestroyedKeys, &operation.Attempts, &operation.ReasonCode, &operation.UpdatedAt, &operation.CompletedAt); err != nil {
			return LifecycleSummary{}, err
		}
		summary.DeletionOperations = append(summary.DeletionOperations, operation)
	}
	if err := operationRows.Err(); err != nil {
		return LifecycleSummary{}, err
	}
	drillRows, err := r.pool.Query(context.Background(), `SELECT drill_id,file_id,version_id,requested_by,outcome,reason_code,verified_at FROM securestore_recovery_drills ORDER BY verified_at DESC LIMIT $1`, limit)
	if err != nil {
		return LifecycleSummary{}, err
	}
	defer drillRows.Close()
	for drillRows.Next() {
		var drill RecoveryDrill
		if err := drillRows.Scan(&drill.DrillID, &drill.FileID, &drill.VersionID, &drill.RequestedBy, &drill.Outcome, &drill.ReasonCode, &drill.VerifiedAt); err != nil {
			return LifecycleSummary{}, err
		}
		summary.RecoveryDrills = append(summary.RecoveryDrills, drill)
	}
	return summary, drillRows.Err()
}

func (r *PostgresRepository) EligibleForPurge(now time.Time, limit int) ([]LifecycleFile, error) {
	if limit < 1 || limit > 100 {
		limit = 25
	}
	rows, err := r.pool.Query(context.Background(), lifecycleSelect+` WHERE deleted_at IS NOT NULL AND purged_at IS NULL AND purge_after<=$1 AND NOT legal_hold AND (retention_until IS NULL OR retention_until<=$1) ORDER BY purge_after LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []LifecycleFile{}
	for rows.Next() {
		file, err := scanLifecycleFileValue(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, file)
	}
	return result, rows.Err()
}

func (r *PostgresRepository) RecordDeletionFailure(ownerID, fileID, operationID, reason string, now time.Time) error {
	_, err := r.pool.Exec(context.Background(), `INSERT INTO securestore_deletion_operations(operation_id,file_id,owner_id,status,destroyed_keys,attempts,reason_code,updated_at,completed_at) VALUES($1,$2,$3,'failed',0,1,$4,$5,NULL) ON CONFLICT(operation_id) DO UPDATE SET status='failed',attempts=securestore_deletion_operations.attempts+1,reason_code=EXCLUDED.reason_code,updated_at=EXCLUDED.updated_at,completed_at=NULL`, operationID, fileID, ownerID, reason, now)
	return err
}

func (r *PostgresRepository) RecordDeletionFailureAudited(ownerID, fileID, operationID, reason string, now time.Time, intent auditoutbox.Intent) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO securestore_deletion_operations(operation_id,file_id,owner_id,status,destroyed_keys,attempts,reason_code,updated_at) VALUES($1,$2,$3,'failed',0,1,$4,$5) ON CONFLICT(operation_id) DO UPDATE SET status='failed',attempts=securestore_deletion_operations.attempts+1,reason_code=EXCLUDED.reason_code,updated_at=EXCLUDED.updated_at`, operationID, fileID, ownerID, reason, now); err != nil {
		return err
	}
	if err := auditoutbox.Enqueue(ctx, tx, intent); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) CurrentMetadataForDrill(fileID string) (Metadata, error) {
	var value Metadata
	err := r.pool.QueryRow(context.Background(), `SELECT p.operation_id,p.version_id,p.owner_id,p.blob_object,p.schema_version,p.algorithm,p.kek_id,p.kek_version,p.wrapping_kek_id,p.wrapping_kek_version,p.wrapped_dek,p.nonce,p.plaintext_size,p.plaintext_digest,p.media_type,p.inspection_record_id,p.created_at FROM securestore_files f JOIN securestore_protected_versions p ON p.version_id=f.current_version_id WHERE f.file_id=$1 AND f.purged_at IS NULL AND p.wrapped_dek IS NOT NULL`, fileID).Scan(&value.UploadID, &value.VersionID, &value.OwnerID, &value.BlobObject, &value.SchemaVersion, &value.Algorithm, &value.KEKID, &value.KEKVersion, &value.WrappingKEKID, &value.WrappingKEKVersion, &value.WrappedDEK, &value.Nonce, &value.PlaintextSize, &value.PlaintextDigest, &value.MediaType, &value.InspectionRecordID, &value.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Metadata{}, ErrNotFound
	}
	return value, err
}

func (r *PostgresRepository) RecordRecoveryDrill(drill RecoveryDrill) error {
	_, err := r.pool.Exec(context.Background(), `INSERT INTO securestore_recovery_drills(drill_id,file_id,version_id,requested_by,outcome,reason_code,verified_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, drill.DrillID, drill.FileID, drill.VersionID, drill.RequestedBy, drill.Outcome, drill.ReasonCode, drill.VerifiedAt)
	return err
}

func (r *PostgresRepository) RecordRecoveryDrillAudited(drill RecoveryDrill, intent auditoutbox.Intent) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO securestore_recovery_drills(drill_id,file_id,version_id,requested_by,outcome,reason_code,verified_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, drill.DrillID, drill.FileID, drill.VersionID, drill.RequestedBy, drill.Outcome, drill.ReasonCode, drill.VerifiedAt); err != nil {
		return err
	}
	if err := auditoutbox.Enqueue(ctx, tx, intent); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const lifecycleSelect = `SELECT file_id,owner_id,name,current_version_id,created_at,updated_at,deleted_at,purge_after,retention_until,legal_hold,legal_hold_reason,purged_at FROM securestore_files`

func scanLifecycleFile(row rowScannerLifecycle, destination ...*LifecycleFile) error {
	var f LifecycleFile
	err := row.Scan(&f.FileID, &f.OwnerID, &f.Name, &f.CurrentVersionID, &f.CreatedAt, &f.UpdatedAt, &f.DeletedAt, &f.PurgeAfter, &f.RetentionUntil, &f.LegalHold, &f.LegalHoldReason, &f.PurgedAt)
	if len(destination) > 0 {
		*destination[0] = f
	}
	return err
}

func scanLifecycleFileValue(row rowScannerLifecycle) (LifecycleFile, error) {
	var file LifecycleFile
	err := scanLifecycleFile(row, &file)
	return file, err
}

type rowScannerLifecycle interface{ Scan(...any) error }

var _ LifecycleRepository = (*PostgresRepository)(nil)
