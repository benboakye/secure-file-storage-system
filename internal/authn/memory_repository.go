package authn

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type verificationRecord struct {
	UserID     string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

type MemoryRepository struct {
	mu             sync.RWMutex
	usersByEmail   map[string]UserRecord
	userEmailByID  map[string]string
	verifications  map[[32]byte]verificationRecord
	sessionsByHash map[[32]byte]Session
	mfaConfigs     map[string]MFAConfiguration
	mfaChallenges  map[[32]byte]MFAChallengeRecord
	recoveryCodes  map[string]map[[32]byte]*time.Time
	stepUpProofs   map[[32]byte]memoryStepUpProof
	invitations    map[[32]byte]PrivilegedInvitation
}
type memoryStepUpProof struct {
	SessionHash [32]byte
	UserID      string
	ExpiresAt   time.Time
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		usersByEmail: make(map[string]UserRecord), userEmailByID: make(map[string]string),
		verifications: make(map[[32]byte]verificationRecord), sessionsByHash: make(map[[32]byte]Session), mfaConfigs: make(map[string]MFAConfiguration), mfaChallenges: make(map[[32]byte]MFAChallengeRecord), recoveryCodes: make(map[string]map[[32]byte]*time.Time), stepUpProofs: make(map[[32]byte]memoryStepUpProof), invitations: make(map[[32]byte]PrivilegedInvitation),
	}
}

func (r *MemoryRepository) CreateUserWithVerification(record UserRecord, tokenHash [32]byte, expiresAt, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.usersByEmail[record.Email]; exists {
		return ErrDuplicateUser
	}
	sentAt := now
	record.VerificationSentAt = &sentAt
	r.usersByEmail[record.Email] = cloneRecord(record)
	r.userEmailByID[record.ID] = record.Email
	r.verifications[tokenHash] = verificationRecord{UserID: record.ID, ExpiresAt: expiresAt}
	return nil
}

func (r *MemoryRepository) UserByEmail(email string) (UserRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, exists := r.usersByEmail[email]
	if !exists {
		return UserRecord{}, ErrUserNotFound
	}
	return cloneRecord(record), nil
}

func (r *MemoryRepository) ReplaceVerificationToken(userID string, tokenHash [32]byte, expiresAt, now time.Time, minimumInterval time.Duration) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	email, exists := r.userEmailByID[userID]
	if !exists {
		return false, ErrUserNotFound
	}
	record := r.usersByEmail[email]
	if record.EmailVerifiedAt != nil {
		return false, nil
	}
	if record.VerificationSentAt != nil && now.Sub(*record.VerificationSentAt) < minimumInterval {
		return false, nil
	}
	for hash, verification := range r.verifications {
		if verification.UserID == userID && verification.ConsumedAt == nil {
			delete(r.verifications, hash)
		}
	}
	sentAt := now
	record.VerificationSentAt = &sentAt
	r.usersByEmail[email] = cloneRecord(record)
	r.verifications[tokenHash] = verificationRecord{UserID: userID, ExpiresAt: expiresAt}
	return true, nil
}

func (r *MemoryRepository) ConsumeVerificationToken(tokenHash [32]byte, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	verification, exists := r.verifications[tokenHash]
	if !exists || verification.ConsumedAt != nil || !now.Before(verification.ExpiresAt) {
		return ErrVerificationToken
	}
	email, exists := r.userEmailByID[verification.UserID]
	if !exists {
		return ErrVerificationToken
	}
	record := r.usersByEmail[email]
	if record.EmailVerifiedAt != nil {
		return ErrVerificationToken
	}
	consumedAt := now
	verification.ConsumedAt = &consumedAt
	r.verifications[tokenHash] = verification
	record.EmailVerifiedAt = &consumedAt
	r.usersByEmail[email] = cloneRecord(record)
	return nil
}

func (r *MemoryRepository) CreateSession(tokenHash [32]byte, session Session, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessionsByHash[tokenHash] = session
	return nil
}

func (r *MemoryRepository) SessionByHash(tokenHash [32]byte, now time.Time) (Session, error) {
	r.mu.RLock()
	session, exists := r.sessionsByHash[tokenHash]
	r.mu.RUnlock()
	if !exists || !now.Before(session.ExpiresAt) {
		if exists {
			r.mu.Lock()
			delete(r.sessionsByHash, tokenHash)
			r.mu.Unlock()
		}
		return Session{}, ErrSessionNotFound
	}
	return session, nil
}

func (r *MemoryRepository) DeleteSession(tokenHash [32]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessionsByHash, tokenHash)
	return nil
}

func (r *MemoryRepository) ListUsers(search string, limit, offset int) ([]AdminUser, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	needle := strings.ToLower(search)
	users := make([]AdminUser, 0, len(r.usersByEmail))
	for _, record := range r.usersByEmail {
		if needle != "" && !strings.Contains(strings.ToLower(record.Name), needle) && !strings.Contains(record.Email, needle) {
			continue
		}
		status := "pending"
		if record.EmailVerifiedAt != nil {
			status = "verified"
		}
		accountStatus := record.AccountStatus
		if record.LockedUntil != nil && record.LockedUntil.After(time.Now().UTC()) {
			accountStatus = "locked"
		}
		users = append(users, AdminUser{
			ID: record.ID, Name: record.Name, Email: record.Email, Role: record.Role,
			VerificationStatus: status, AccountStatus: accountStatus,
			EmailVerifiedAt: cloneTime(record.EmailVerifiedAt), CreatedAt: record.CreatedAt,
		})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].CreatedAt.After(users[j].CreatedAt) })
	total := len(users)
	if offset >= total {
		return []AdminUser{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return users[offset:end], total, nil
}

func (r *MemoryRepository) UpdateUserStatusAndDeleteSessions(userID, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	email, exists := r.userEmailByID[userID]
	if !exists {
		return ErrUserNotFound
	}
	record := r.usersByEmail[email]
	record.AccountStatus = status
	if status == "active" {
		record.FailedLoginAttempts = 0
		record.FailedLoginWindowStartedAt = nil
		record.LockedUntil = nil
	}
	r.usersByEmail[email] = cloneRecord(record)
	for hash, session := range r.sessionsByHash {
		if session.User.ID == userID {
			delete(r.sessionsByHash, hash)
		}
	}
	return nil
}

func (r *MemoryRepository) DeleteSessionsForUser(userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.userEmailByID[userID]; !exists {
		return ErrUserNotFound
	}
	for hash, session := range r.sessionsByHash {
		if session.User.ID == userID {
			delete(r.sessionsByHash, hash)
		}
	}
	return nil
}

func (r *MemoryRepository) UserExists(userID string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.userEmailByID[userID]
	return exists, nil
}

func (r *MemoryRepository) UserRole(userID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	email, exists := r.userEmailByID[userID]
	if !exists {
		return "", ErrUserNotFound
	}
	return r.usersByEmail[email].Role, nil
}

func (r *MemoryRepository) RecordAuthenticationFailure(userID string, now time.Time, window time.Duration, threshold int, lockDuration time.Duration) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	email, ok := r.userEmailByID[userID]
	if !ok {
		return false, ErrUserNotFound
	}
	record := r.usersByEmail[email]
	if record.FailedLoginWindowStartedAt == nil || !record.FailedLoginWindowStartedAt.After(now.Add(-window)) {
		record.FailedLoginAttempts = 0
		start := now
		record.FailedLoginWindowStartedAt = &start
	}
	record.FailedLoginAttempts++
	if record.FailedLoginAttempts >= threshold {
		until := now.Add(lockDuration)
		record.LockedUntil = &until
	}
	r.usersByEmail[email] = cloneRecord(record)
	locked := record.LockedUntil != nil && record.LockedUntil.After(now)
	if locked {
		for hash, session := range r.sessionsByHash {
			if session.User.ID == userID {
				delete(r.sessionsByHash, hash)
			}
		}
	}
	return locked, nil
}
func (r *MemoryRepository) ClearAuthenticationFailures(userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	email, ok := r.userEmailByID[userID]
	if !ok {
		return ErrUserNotFound
	}
	record := r.usersByEmail[email]
	record.FailedLoginAttempts = 0
	record.FailedLoginWindowStartedAt = nil
	record.LockedUntil = nil
	r.usersByEmail[email] = cloneRecord(record)
	return nil
}

func (r *MemoryRepository) UpdateUserRole(email, role string) error {
	if role != "user" && role != "auditor" && role != "admin" {
		return ErrInvalidInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.usersByEmail[normalizeEmail(email)]
	if !exists {
		return ErrUserNotFound
	}
	record.Role = role
	r.usersByEmail[record.Email] = cloneRecord(record)
	// A role change invalidates every existing session. This prevents a session
	// authenticated under the standard-user policy from gaining privileges
	// without a fresh login through the privileged authentication boundary.
	for hash, session := range r.sessionsByHash {
		if session.User.ID == record.ID {
			delete(r.sessionsByHash, hash)
		}
	}
	return nil
}

func (r *MemoryRepository) MFAConfiguration(userID string) (MFAConfiguration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, ok := r.mfaConfigs[userID]
	if !ok {
		return MFAConfiguration{}, ErrMFANotConfigured
	}
	value.SecretCiphertext = append([]byte(nil), value.SecretCiphertext...)
	value.SecretNonce = append([]byte(nil), value.SecretNonce...)
	return value, nil
}
func (r *MemoryRepository) CreateMFAChallenge(hash [32]byte, challenge MFAChallengeRecord, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mfaChallenges[hash] = challenge
	return nil
}
func (r *MemoryRepository) ConsumeMFAChallenge(hash [32]byte, now time.Time) (MFAChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	challenge, ok := r.mfaChallenges[hash]
	if !ok || !now.Before(challenge.ExpiresAt) {
		return MFAChallengeRecord{}, ErrMFAChallenge
	}
	delete(r.mfaChallenges, hash)
	return challenge, nil
}
func (r *MemoryRepository) ConfirmMFA(userID string, ciphertext, nonce []byte, lastCounter int64, hashes [][32]byte, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.mfaConfigs[userID]; exists {
		return ErrMFAInvalid
	}
	r.mfaConfigs[userID] = MFAConfiguration{UserID: userID, SecretCiphertext: append([]byte(nil), ciphertext...), SecretNonce: append([]byte(nil), nonce...), ConfirmedAt: now, LastCounter: lastCounter}
	r.recoveryCodes[userID] = make(map[[32]byte]*time.Time)
	for _, hash := range hashes {
		r.recoveryCodes[userID][hash] = nil
	}
	return nil
}
func (r *MemoryRepository) AdvanceMFACounter(userID string, counter int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.mfaConfigs[userID]
	if !ok {
		return false, ErrMFANotConfigured
	}
	if counter <= value.LastCounter {
		return false, nil
	}
	value.LastCounter = counter
	r.mfaConfigs[userID] = value
	return true, nil
}
func (r *MemoryRepository) ConsumeMFARecoveryCode(userID string, hash [32]byte, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	codes := r.recoveryCodes[userID]
	used, ok := codes[hash]
	if !ok || used != nil {
		return false, nil
	}
	value := now
	codes[hash] = &value
	return true, nil
}

var _ MFARepository = (*MemoryRepository)(nil)

func (r *MemoryRepository) CreateStepUpProof(tokenHash, sessionHash [32]byte, userID string, expiresAt, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stepUpProofs[tokenHash] = memoryStepUpProof{SessionHash: sessionHash, UserID: userID, ExpiresAt: expiresAt}
	return nil
}
func (r *MemoryRepository) StepUpProofValid(tokenHash, sessionHash [32]byte, userID string, now time.Time) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	proof, ok := r.stepUpProofs[tokenHash]
	session, sessionExists := r.sessionsByHash[sessionHash]
	return ok && sessionExists && session.User.ID == userID && now.Before(session.ExpiresAt) && proof.SessionHash == sessionHash && proof.UserID == userID && now.Before(proof.ExpiresAt), nil
}

var _ StepUpRepository = (*MemoryRepository)(nil)

func (r *MemoryRepository) CreatePrivilegedInvitation(tokenHash [32]byte, invitation PrivilegedInvitation, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.usersByEmail[invitation.Email]; exists {
		return ErrDuplicateUser
	}
	for _, pending := range r.invitations {
		if pending.Email == invitation.Email {
			return ErrDuplicateUser
		}
	}
	r.invitations[tokenHash] = invitation
	return nil
}

func (r *MemoryRepository) AcceptPrivilegedInvitation(tokenHash [32]byte, record UserRecord, now time.Time) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	invitation, exists := r.invitations[tokenHash]
	if !exists || !now.Before(invitation.ExpiresAt) {
		return User{}, ErrInvitationToken
	}
	if _, exists := r.usersByEmail[invitation.Email]; exists {
		return User{}, ErrDuplicateUser
	}
	verifiedAt := now
	record.Name, record.Email, record.Role, record.EmailVerifiedAt = invitation.Name, invitation.Email, invitation.Role, &verifiedAt
	r.usersByEmail[record.Email] = cloneRecord(record)
	r.userEmailByID[record.ID] = record.Email
	delete(r.invitations, tokenHash)
	return record.User, nil
}

var _ PrivilegedInvitationRepository = (*MemoryRepository)(nil)

func cloneRecord(record UserRecord) UserRecord {
	record.PasswordHash = append([]byte(nil), record.PasswordHash...)
	if record.EmailVerifiedAt != nil {
		value := *record.EmailVerifiedAt
		record.EmailVerifiedAt = &value
	}
	if record.VerificationSentAt != nil {
		value := *record.VerificationSentAt
		record.VerificationSentAt = &value
	}
	if record.FailedLoginWindowStartedAt != nil {
		value := *record.FailedLoginWindowStartedAt
		record.FailedLoginWindowStartedAt = &value
	}
	if record.LockedUntil != nil {
		value := *record.LockedUntil
		record.LockedUntil = &value
	}
	return record
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

var _ Repository = (*MemoryRepository)(nil)
