package authn

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

//go:embed migrations/001_auth.sql
var authMigration string

//go:embed migrations/002_session_audience.sql
var sessionAudienceMigration string

//go:embed migrations/003_account_status.sql
var accountStatusMigration string

//go:embed migrations/004_privileged_mfa.sql
var privilegedMFAMigration string

//go:embed migrations/005_authentication_lockout.sql
var authenticationLockoutMigration string

//go:embed migrations/006_step_up_authorization.sql
var stepUpAuthorizationMigration string

//go:embed migrations/007_privileged_invitations.sql
var privilegedInvitationsMigration string

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
	for _, migration := range []string{authMigration, sessionAudienceMigration, accountStatusMigration, privilegedMFAMigration, authenticationLockoutMigration, stepUpAuthorizationMigration, privilegedInvitationsMigration} {
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

func (r *PostgresRepository) Close() { r.pool.Close() }

func (r *PostgresRepository) CreateUserWithVerification(record UserRecord, tokenHash [32]byte, expiresAt, now time.Time) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO securestore_users
			(id, name, email, password_hash, role, verification_sent_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6)`,
		record.ID, record.Name, record.Email, record.PasswordHash, record.Role, now)
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return ErrDuplicateUser
		}
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO securestore_email_verification_tokens
			(token_hash, user_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4)`, tokenHash[:], record.ID, expiresAt, now)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) UserByEmail(email string) (UserRecord, error) {
	var record UserRecord
	err := r.pool.QueryRow(context.Background(), `
		SELECT id, name, email, role, password_hash, email_verified_at, verification_sent_at, created_at,
			CASE WHEN locked_until > now() THEN 'locked' ELSE account_status END,
			failed_login_attempts,failed_login_window_started_at,locked_until
		FROM securestore_users WHERE email = $1`, email).Scan(
		&record.ID, &record.Name, &record.Email, &record.Role, &record.PasswordHash,
		&record.EmailVerifiedAt, &record.VerificationSentAt, &record.CreatedAt, &record.AccountStatus,
		&record.FailedLoginAttempts, &record.FailedLoginWindowStartedAt, &record.LockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserRecord{}, ErrUserNotFound
	}
	return record, err
}

func (r *PostgresRepository) ReplaceVerificationToken(userID string, tokenHash [32]byte, expiresAt, now time.Time, minimumInterval time.Duration) (bool, error) {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var verifiedAt, sentAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT email_verified_at, verification_sent_at
		FROM securestore_users WHERE id = $1 FOR UPDATE`, userID).Scan(&verifiedAt, &sentAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrUserNotFound
	}
	if err != nil {
		return false, err
	}
	if verifiedAt != nil || (sentAt != nil && now.Sub(*sentAt) < minimumInterval) {
		return false, tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM securestore_email_verification_tokens WHERE user_id = $1 AND consumed_at IS NULL`, userID); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO securestore_email_verification_tokens
			(token_hash, user_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4)`, tokenHash[:], userID, expiresAt, now); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE securestore_users SET verification_sent_at = $2 WHERE id = $1`, userID, now); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (r *PostgresRepository) ConsumeVerificationToken(tokenHash [32]byte, now time.Time) error {
	result, err := r.pool.Exec(context.Background(), `
		WITH consumed AS (
			UPDATE securestore_email_verification_tokens
			SET consumed_at = $2
			WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
			RETURNING user_id
		)
		UPDATE securestore_users AS users
		SET email_verified_at = $2
		FROM consumed
		WHERE users.id = consumed.user_id AND users.email_verified_at IS NULL`, tokenHash[:], now)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrVerificationToken
	}
	return nil
}

func (r *PostgresRepository) CreateSession(tokenHash [32]byte, session Session, createdAt time.Time) error {
	_, err := r.pool.Exec(context.Background(), `
		INSERT INTO securestore_sessions (token_hash, user_id, audience, csrf_token, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, tokenHash[:], session.User.ID, session.Audience, session.CSRFToken, session.ExpiresAt, createdAt)
	return err
}

func (r *PostgresRepository) SessionByHash(tokenHash [32]byte, now time.Time) (Session, error) {
	var session Session
	err := r.pool.QueryRow(context.Background(), `
		SELECT users.id, users.name, users.email, users.role, sessions.audience, sessions.csrf_token, sessions.expires_at
		FROM securestore_sessions AS sessions
		JOIN securestore_users AS users ON users.id = sessions.user_id
		WHERE sessions.token_hash = $1 AND sessions.expires_at > $2
			AND users.email_verified_at IS NOT NULL AND users.account_status = 'active'`, tokenHash[:], now).Scan(
		&session.User.ID, &session.User.Name, &session.User.Email, &session.User.Role, &session.Audience, &session.CSRFToken, &session.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrSessionNotFound
	}
	return session, err
}

func (r *PostgresRepository) DeleteSession(tokenHash [32]byte) error {
	_, err := r.pool.Exec(context.Background(), `DELETE FROM securestore_sessions WHERE token_hash = $1`, tokenHash[:])
	return err
}

func (r *PostgresRepository) ListUsers(search string, limit, offset int) ([]AdminUser, int, error) {
	ctx := context.Background()
	var total int
	err := r.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM securestore_users
		WHERE $1 = '' OR name ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%'`, search).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, email, role,
			CASE WHEN email_verified_at IS NULL THEN 'pending' ELSE 'verified' END,
			CASE WHEN locked_until > now() THEN 'locked' ELSE account_status END, email_verified_at, created_at
		FROM securestore_users
		WHERE $1 = '' OR name ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%'
		ORDER BY created_at DESC, id
		LIMIT $2 OFFSET $3`, search, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	users := make([]AdminUser, 0, limit)
	for rows.Next() {
		var user AdminUser
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.VerificationStatus, &user.AccountStatus, &user.EmailVerifiedAt, &user.CreatedAt); err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (r *PostgresRepository) UpdateUserStatusAndDeleteSessions(userID, status string) error {
	return r.updateUserStatusAndDeleteSessions(userID, status, nil)
}

func (r *PostgresRepository) UpdateUserStatusAndDeleteSessionsAudited(userID, status string, intent auditoutbox.Intent) error {
	return r.updateUserStatusAndDeleteSessions(userID, status, &intent)
}

func (r *PostgresRepository) updateUserStatusAndDeleteSessions(userID, status string, intent *auditoutbox.Intent) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `UPDATE securestore_users SET account_status=$2,failed_login_attempts=CASE WHEN $2='active' THEN 0 ELSE failed_login_attempts END,failed_login_window_started_at=CASE WHEN $2='active' THEN NULL ELSE failed_login_window_started_at END,locked_until=CASE WHEN $2='active' THEN NULL ELSE locked_until END WHERE id=$1`, userID, status)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrUserNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM securestore_sessions WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) DeleteSessionsForUser(userID string) error {
	return r.deleteSessionsForUser(userID, nil)
}

func (r *PostgresRepository) DeleteSessionsForUserAudited(userID string, intent auditoutbox.Intent) error {
	return r.deleteSessionsForUser(userID, &intent)
}

func (r *PostgresRepository) deleteSessionsForUser(userID string, intent *auditoutbox.Intent) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM securestore_users WHERE id = $1)`, userID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrUserNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM securestore_sessions WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if intent != nil {
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) UserExists(userID string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM securestore_users WHERE id = $1)`, userID).Scan(&exists)
	return exists, err
}

func (r *PostgresRepository) UserRole(userID string) (string, error) {
	var role string
	err := r.pool.QueryRow(context.Background(), `SELECT role FROM securestore_users WHERE id = $1`, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUserNotFound
	}
	return role, err
}

func (r *PostgresRepository) RecordAuthenticationFailure(userID string, now time.Time, window time.Duration, threshold int, lockDuration time.Duration) (bool, error) {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var lockedUntil *time.Time
	err = tx.QueryRow(ctx, `UPDATE securestore_users SET failed_login_attempts=CASE WHEN failed_login_window_started_at IS NULL OR failed_login_window_started_at<=$2 THEN 1 ELSE failed_login_attempts+1 END,failed_login_window_started_at=CASE WHEN failed_login_window_started_at IS NULL OR failed_login_window_started_at<=$2 THEN $1 ELSE failed_login_window_started_at END,locked_until=CASE WHEN (CASE WHEN failed_login_window_started_at IS NULL OR failed_login_window_started_at<=$2 THEN 1 ELSE failed_login_attempts+1 END)>=$3 THEN $4 ELSE locked_until END WHERE id=$5 RETURNING locked_until`, now, now.Add(-window), threshold, now.Add(lockDuration), userID).Scan(&lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrUserNotFound
	}
	if err != nil {
		return false, err
	}
	locked := lockedUntil != nil && lockedUntil.After(now)
	if locked {
		if _, err = tx.Exec(ctx, `DELETE FROM securestore_sessions WHERE user_id=$1`, userID); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	return locked, nil
}
func (r *PostgresRepository) ClearAuthenticationFailures(userID string) error {
	_, err := r.pool.Exec(context.Background(), `UPDATE securestore_users SET failed_login_attempts=0,failed_login_window_started_at=NULL,locked_until=NULL WHERE id=$1`, userID)
	return err
}

func (r *PostgresRepository) MFAConfiguration(userID string) (MFAConfiguration, error) {
	var configuration MFAConfiguration
	err := r.pool.QueryRow(context.Background(), `SELECT user_id,secret_ciphertext,secret_nonce,confirmed_at,last_counter FROM securestore_user_mfa WHERE user_id=$1`, userID).Scan(&configuration.UserID, &configuration.SecretCiphertext, &configuration.SecretNonce, &configuration.ConfirmedAt, &configuration.LastCounter)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAConfiguration{}, ErrMFANotConfigured
	}
	return configuration, err
}

func (r *PostgresRepository) CreateMFAChallenge(tokenHash [32]byte, challenge MFAChallengeRecord, now time.Time) error {
	_, err := r.pool.Exec(context.Background(), `INSERT INTO securestore_mfa_challenges(token_hash,user_id,pending_secret_ciphertext,pending_secret_nonce,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6)`, tokenHash[:], challenge.User.ID, nullableBytes(challenge.PendingSecretCiphertext), nullableBytes(challenge.PendingSecretNonce), challenge.ExpiresAt, now)
	return err
}

func (r *PostgresRepository) ConsumeMFAChallenge(tokenHash [32]byte, now time.Time) (MFAChallengeRecord, error) {
	var challenge MFAChallengeRecord
	err := r.pool.QueryRow(context.Background(), `WITH consumed AS (UPDATE securestore_mfa_challenges SET consumed_at=$2 WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>$2 RETURNING user_id,pending_secret_ciphertext,pending_secret_nonce,expires_at) SELECT u.id,u.name,u.email,u.role,c.pending_secret_ciphertext,c.pending_secret_nonce,c.expires_at FROM consumed c JOIN securestore_users u ON u.id=c.user_id WHERE u.account_status='active' AND u.role IN ('admin','auditor')`, tokenHash[:], now).Scan(&challenge.User.ID, &challenge.User.Name, &challenge.User.Email, &challenge.User.Role, &challenge.PendingSecretCiphertext, &challenge.PendingSecretNonce, &challenge.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAChallengeRecord{}, ErrMFAChallenge
	}
	return challenge, err
}

func (r *PostgresRepository) ConfirmMFA(userID string, ciphertext, nonce []byte, lastCounter int64, recoveryCodeHashes [][32]byte, now time.Time) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `INSERT INTO securestore_user_mfa(user_id,secret_ciphertext,secret_nonce,confirmed_at,last_counter) VALUES($1,$2,$3,$4,$5) ON CONFLICT(user_id) DO NOTHING`, userID, ciphertext, nonce, now, lastCounter)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrMFAInvalid
	}
	for _, hash := range recoveryCodeHashes {
		if _, err = tx.Exec(ctx, `INSERT INTO securestore_mfa_recovery_codes(user_id,code_hash,created_at) VALUES($1,$2,$3)`, userID, hash[:], now); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) AdvanceMFACounter(userID string, counter int64) (bool, error) {
	result, err := r.pool.Exec(context.Background(), `UPDATE securestore_user_mfa SET last_counter=$2 WHERE user_id=$1 AND last_counter<$2`, userID, counter)
	return err == nil && result.RowsAffected() == 1, err
}
func (r *PostgresRepository) ConsumeMFARecoveryCode(userID string, codeHash [32]byte, now time.Time) (bool, error) {
	result, err := r.pool.Exec(context.Background(), `UPDATE securestore_mfa_recovery_codes SET used_at=$3 WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL`, userID, codeHash[:], now)
	return err == nil && result.RowsAffected() == 1, err
}
func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

var _ MFARepository = (*PostgresRepository)(nil)

func (r *PostgresRepository) CreateStepUpProof(tokenHash, sessionHash [32]byte, userID string, expiresAt, now time.Time) error {
	_, err := r.pool.Exec(context.Background(), `INSERT INTO securestore_step_up_proofs(token_hash,session_token_hash,user_id,expires_at,created_at) VALUES($1,$2,$3,$4,$5)`, tokenHash[:], sessionHash[:], userID, expiresAt, now)
	return err
}
func (r *PostgresRepository) StepUpProofValid(tokenHash, sessionHash [32]byte, userID string, now time.Time) (bool, error) {
	var valid bool
	err := r.pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM securestore_step_up_proofs p JOIN securestore_sessions s ON s.token_hash=p.session_token_hash WHERE p.token_hash=$1 AND p.session_token_hash=$2 AND p.user_id=$3 AND p.expires_at>$4 AND s.expires_at>$4)`, tokenHash[:], sessionHash[:], userID, now).Scan(&valid)
	return valid, err
}

var _ StepUpRepository = (*PostgresRepository)(nil)

func (r *PostgresRepository) CreatePrivilegedInvitation(tokenHash [32]byte, invitation PrivilegedInvitation, now time.Time) error {
	_, err := r.pool.Exec(context.Background(), `INSERT INTO securestore_privileged_invitations(token_hash,invited_by,name,email,role,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, tokenHash[:], invitation.InvitedBy, invitation.Name, invitation.Email, invitation.Role, invitation.ExpiresAt, now)
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return ErrDuplicateUser
		}
	}
	return err
}

func (r *PostgresRepository) CreatePrivilegedInvitationAudited(tokenHash [32]byte, invitation PrivilegedInvitation, now time.Time, intent auditoutbox.Intent) error {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO securestore_privileged_invitations(token_hash,invited_by,name,email,role,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, tokenHash[:], invitation.InvitedBy, invitation.Name, invitation.Email, invitation.Role, invitation.ExpiresAt, now)
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return ErrDuplicateUser
		}
		return err
	}
	if err := auditoutbox.Enqueue(ctx, tx, intent); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) AcceptPrivilegedInvitation(tokenHash [32]byte, record UserRecord, now time.Time) (User, error) {
	return r.acceptPrivilegedInvitation(tokenHash, record, now, nil)
}

func (r *PostgresRepository) AcceptPrivilegedInvitationAudited(tokenHash [32]byte, record UserRecord, now time.Time, intent auditoutbox.Intent) (User, error) {
	return r.acceptPrivilegedInvitation(tokenHash, record, now, &intent)
}

func (r *PostgresRepository) acceptPrivilegedInvitation(tokenHash [32]byte, record UserRecord, now time.Time, intent *auditoutbox.Intent) (User, error) {
	ctx := context.Background()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var invitation PrivilegedInvitation
	err = tx.QueryRow(ctx, `UPDATE securestore_privileged_invitations SET accepted_at=$2 WHERE token_hash=$1 AND accepted_at IS NULL AND expires_at>$2 RETURNING name,email,role`, tokenHash[:], now).Scan(&invitation.Name, &invitation.Email, &invitation.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrInvitationToken
	}
	if err != nil {
		return User{}, err
	}
	verifiedAt := now
	record.Name, record.Email, record.Role, record.EmailVerifiedAt = invitation.Name, invitation.Email, invitation.Role, &verifiedAt
	_, err = tx.Exec(ctx, `INSERT INTO securestore_users(id,name,email,password_hash,role,email_verified_at,created_at,account_status) VALUES($1,$2,$3,$4,$5,$6,$7,'active')`, record.ID, record.Name, record.Email, record.PasswordHash, record.Role, verifiedAt, now)
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return User{}, ErrDuplicateUser
		}
		return User{}, err
	}
	if intent != nil {
		intent.ActorID, intent.ResourceID, intent.ToState = record.ID, record.ID, record.Role
		if err := auditoutbox.Enqueue(ctx, tx, *intent); err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}
	return record.User, nil
}

var _ PrivilegedInvitationRepository = (*PostgresRepository)(nil)

var _ Repository = (*PostgresRepository)(nil)
