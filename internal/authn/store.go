package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"securestore/internal/auditoutbox"
)

const passwordHashCost = 12

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailNotVerified   = errors.New("email address is not verified")
	ErrRegistration       = errors.New("unable to register account")
	ErrInvalidInput       = errors.New("invalid account input")
	ErrSessionNotFound    = errors.New("session not found")
	ErrVerificationToken  = errors.New("verification token is invalid or expired")
	ErrUserNotFound       = errors.New("user not found")
	ErrDuplicateUser      = errors.New("user already exists")
	ErrSelfManagement     = errors.New("administrators cannot change their own account status")
	ErrMFAInvalid         = errors.New("multi-factor authentication code is invalid")
	ErrMFAChallenge       = errors.New("multi-factor authentication challenge is invalid or expired")
	ErrMFANotConfigured   = errors.New("multi-factor authentication is not configured")
	ErrStepUpRequired     = errors.New("recent step-up authentication is required")
)

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type AdminUser struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Email              string     `json:"email"`
	Role               string     `json:"role"`
	VerificationStatus string     `json:"verificationStatus"`
	AccountStatus      string     `json:"accountStatus"`
	EmailVerifiedAt    *time.Time `json:"emailVerifiedAt,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
}

type AdminUserPage struct {
	Users  []AdminUser `json:"users"`
	Total  int         `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

type UserRecord struct {
	User
	PasswordHash               []byte
	EmailVerifiedAt            *time.Time
	VerificationSentAt         *time.Time
	CreatedAt                  time.Time
	AccountStatus              string
	FailedLoginAttempts        int
	FailedLoginWindowStartedAt *time.Time
	LockedUntil                *time.Time
}

type Session struct {
	User      User
	Audience  string
	CSRFToken string
	ExpiresAt time.Time
}

const (
	// SessionAudienceUser is issued only after the standard-user login policy
	// accepts an account. Privileged identities cannot use this audience.
	SessionAudienceUser = "user"
	// SessionAudiencePrivileged marks sessions created through the dedicated
	// administrator/auditor login boundary.
	SessionAudiencePrivileged = "privileged"
)

type Repository interface {
	CreateUserWithVerification(record UserRecord, tokenHash [32]byte, expiresAt, now time.Time) error
	UserByEmail(email string) (UserRecord, error)
	ReplaceVerificationToken(userID string, tokenHash [32]byte, expiresAt, now time.Time, minimumInterval time.Duration) (bool, error)
	ConsumeVerificationToken(tokenHash [32]byte, now time.Time) error
	CreateSession(tokenHash [32]byte, session Session, createdAt time.Time) error
	SessionByHash(tokenHash [32]byte, now time.Time) (Session, error)
	DeleteSession(tokenHash [32]byte) error
	ListUsers(search string, limit, offset int) ([]AdminUser, int, error)
	UpdateUserStatusAndDeleteSessions(userID, status string) error
	DeleteSessionsForUser(userID string) error
	UserExists(userID string) (bool, error)
	UserRole(userID string) (string, error)
	RecordAuthenticationFailure(userID string, now time.Time, window time.Duration, threshold int, lockDuration time.Duration) (bool, error)
	ClearAuthenticationFailures(userID string) error
}

type auditedIdentityRepository interface {
	UpdateUserStatusAndDeleteSessionsAudited(string, string, auditoutbox.Intent) error
	DeleteSessionsForUserAudited(string, auditoutbox.Intent) error
}

type VerificationMessage struct {
	To              string
	Name            string
	VerificationURL string
	ExpiresAt       time.Time
}

type VerificationMailer interface {
	SendVerification(message VerificationMessage) error
}

type Config struct {
	Repository            Repository
	Mailer                VerificationMailer
	SessionTTL            time.Duration
	VerificationTTL       time.Duration
	VerificationMinResend time.Duration
	PublicAppURL          string
	RequirePrivilegedMFA  bool
	MFAEncryptionKey      []byte
	MFAIssuer             string
	LoginFailureWindow    time.Duration
	LoginFailureThreshold int
	AccountLockDuration   time.Duration
	StepUpTTL             time.Duration
	RequireAdminStepUp    bool
}

type Store struct {
	repository            Repository
	mailer                VerificationMailer
	dummyHash             []byte
	sessionTTL            time.Duration
	verificationTTL       time.Duration
	verificationMinResend time.Duration
	publicAppURL          string
	requirePrivilegedMFA  bool
	mfaEncryptionKey      []byte
	mfaIssuer             string
	loginFailureWindow    time.Duration
	loginFailureThreshold int
	accountLockDuration   time.Duration
	stepUpTTL             time.Duration
	requireAdminStepUp    bool
	now                   func() time.Time
}

// SecurityPosture exposes configuration facts that are safe for privileged
// operators. It deliberately excludes hashes, tokens, cookie values, and
// repository connection details.
type SecurityPosture struct {
	PasswordHashAlgorithm     string `json:"passwordHashAlgorithm"`
	PasswordHashCost          int    `json:"passwordHashCost"`
	SessionTTLSeconds         int64  `json:"sessionTtlSeconds"`
	VerificationTTLSeconds    int64  `json:"verificationTtlSeconds"`
	EmailVerificationRequired bool   `json:"emailVerificationRequired"`
	OpaqueServerSessions      bool   `json:"opaqueServerSessions"`
	CSRFProtection            bool   `json:"csrfProtection"`
	PrivilegedBoundary        bool   `json:"privilegedBoundary"`
	MFAEnforced               bool   `json:"mfaEnforced"`
	AccountLockoutEnabled     bool   `json:"accountLockoutEnabled"`
	LoginFailureThreshold     int    `json:"loginFailureThreshold"`
	LoginFailureWindowSeconds int64  `json:"loginFailureWindowSeconds"`
	AccountLockSeconds        int64  `json:"accountLockSeconds"`
	AdminStepUpEnforced       bool   `json:"adminStepUpEnforced"`
	StepUpTTLSeconds          int64  `json:"stepUpTtlSeconds"`
}

type PersistencePosture struct {
	Durable bool   `json:"durable"`
	Driver  string `json:"driver"`
}

func NewStore(sessionTTL time.Duration) (*Store, error) {
	return NewStoreWithConfig(Config{Repository: NewMemoryRepository(), Mailer: DiscardMailer{}, SessionTTL: sessionTTL})
}

func NewStoreWithConfig(config Config) (*Store, error) {
	if config.Repository == nil {
		return nil, errors.New("authentication repository is required")
	}
	if config.Mailer == nil {
		return nil, errors.New("verification mailer is required")
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = 8 * time.Hour
	}
	if config.VerificationTTL <= 0 {
		config.VerificationTTL = 30 * time.Minute
	}
	if config.VerificationMinResend <= 0 {
		config.VerificationMinResend = time.Minute
	}
	if strings.TrimSpace(config.PublicAppURL) == "" {
		config.PublicAppURL = "http://127.0.0.1:5173"
	}
	if config.RequirePrivilegedMFA && len(config.MFAEncryptionKey) != 32 {
		return nil, errors.New("privileged MFA requires a 32-byte encryption key")
	}
	if strings.TrimSpace(config.MFAIssuer) == "" {
		config.MFAIssuer = "SecureStore"
	}
	if config.LoginFailureWindow <= 0 {
		config.LoginFailureWindow = 15 * time.Minute
	}
	if config.LoginFailureThreshold <= 0 {
		config.LoginFailureThreshold = 5
	}
	if config.AccountLockDuration <= 0 {
		config.AccountLockDuration = 15 * time.Minute
	}
	if config.StepUpTTL <= 0 {
		config.StepUpTTL = 5 * time.Minute
	}
	dummyHash, err := bcrypt.GenerateFromPassword(passwordMaterial("not-a-real-password-value"), passwordHashCost)
	if err != nil {
		return nil, err
	}
	return &Store{
		repository: config.Repository, mailer: config.Mailer, dummyHash: dummyHash,
		sessionTTL: config.SessionTTL, verificationTTL: config.VerificationTTL,
		verificationMinResend: config.VerificationMinResend,
		publicAppURL:          strings.TrimRight(config.PublicAppURL, "/"), now: time.Now,
		requirePrivilegedMFA: config.RequirePrivilegedMFA, mfaEncryptionKey: append([]byte(nil), config.MFAEncryptionKey...), mfaIssuer: config.MFAIssuer,
		loginFailureWindow: config.LoginFailureWindow, loginFailureThreshold: config.LoginFailureThreshold, accountLockDuration: config.AccountLockDuration,
		stepUpTTL:          config.StepUpTTL,
		requireAdminStepUp: config.RequireAdminStepUp,
	}, nil
}

// Register creates an unverified account and deliberately does not create a session.
func (s *Store) Register(name, email, password string) error {
	name = strings.TrimSpace(name)
	email = normalizeEmail(email)
	if !validName(name) || !validEmail(email) || !strongPassword(password) {
		return ErrInvalidInput
	}

	passwordHash, err := bcrypt.GenerateFromPassword(passwordMaterial(password), passwordHashCost)
	if err != nil {
		return err
	}
	userID, err := opaqueID("usr")
	if err != nil {
		return err
	}
	rawToken, err := randomToken(32)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	record := UserRecord{
		User:         User{ID: userID, Name: name, Email: email, Role: "user"},
		PasswordHash: passwordHash, CreatedAt: now, AccountStatus: "active",
	}
	if err := s.repository.CreateUserWithVerification(record, sha256.Sum256([]byte(rawToken)), now.Add(s.verificationTTL), now); err != nil {
		// Duplicate registrations are intentionally indistinguishable from accepted requests.
		if errors.Is(err, ErrDuplicateUser) {
			return nil
		}
		return ErrRegistration
	}
	if err := s.deliverVerification(record.User, rawToken, now.Add(s.verificationTTL)); err != nil {
		return err
	}
	return nil
}

func (s *Store) SecurityPosture() SecurityPosture {
	return SecurityPosture{
		PasswordHashAlgorithm: "bcrypt", PasswordHashCost: passwordHashCost,
		SessionTTLSeconds: int64(s.sessionTTL.Seconds()), VerificationTTLSeconds: int64(s.verificationTTL.Seconds()),
		EmailVerificationRequired: true, OpaqueServerSessions: true, CSRFProtection: true,
		PrivilegedBoundary: true, MFAEnforced: s.requirePrivilegedMFA, AccountLockoutEnabled: true,
		LoginFailureThreshold: s.loginFailureThreshold, LoginFailureWindowSeconds: int64(s.loginFailureWindow.Seconds()), AccountLockSeconds: int64(s.accountLockDuration.Seconds()),
		AdminStepUpEnforced: s.requireAdminStepUp, StepUpTTLSeconds: int64(s.stepUpTTL.Seconds()),
	}
}

// PersistencePosture exposes only the storage class. Connection strings,
// database hosts, credentials, and pool internals remain private.
func (s *Store) PersistencePosture() PersistencePosture {
	if _, ok := s.repository.(*PostgresRepository); ok {
		return PersistencePosture{Durable: true, Driver: "postgresql"}
	}
	return PersistencePosture{Durable: false, Driver: "memory"}
}

func (s *Store) ResendVerification(email string) error {
	email = normalizeEmail(email)
	if !validEmail(email) {
		return nil
	}
	record, err := s.repository.UserByEmail(email)
	if err != nil || record.EmailVerifiedAt != nil {
		return nil
	}
	rawToken, err := randomToken(32)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	replaced, err := s.repository.ReplaceVerificationToken(record.ID, sha256.Sum256([]byte(rawToken)), now.Add(s.verificationTTL), now, s.verificationMinResend)
	if err != nil || !replaced {
		return err
	}
	return s.deliverVerification(record.User, rawToken, now.Add(s.verificationTTL))
}

func (s *Store) VerifyEmail(token string) error {
	token = strings.TrimSpace(token)
	if len(token) < 32 || len(token) > 256 {
		return ErrVerificationToken
	}
	if err := s.repository.ConsumeVerificationToken(sha256.Sum256([]byte(token)), s.now().UTC()); err != nil {
		if errors.Is(err, ErrVerificationToken) {
			return ErrVerificationToken
		}
		return err
	}
	return nil
}

func (s *Store) Login(email, password string) (User, string, Session, error) {
	return s.loginForAudience(email, password, SessionAudienceUser)
}

// LoginPrivileged authenticates only administrator and auditor identities.
// Role mismatches deliberately use ErrInvalidCredentials so the endpoint does
// not disclose whether a submitted address belongs to a privileged account.
func (s *Store) LoginPrivileged(email, password string) (User, string, Session, error) {
	return s.loginForAudience(email, password, SessionAudiencePrivileged)
}

func (s *Store) loginForAudience(email, password, audience string) (User, string, Session, error) {
	record, err := s.verifyCredentials(email, password, audience)
	if err != nil {
		return User{}, "", Session{}, err
	}
	if err := s.repository.ClearAuthenticationFailures(record.ID); err != nil {
		return User{}, "", Session{}, err
	}
	return s.createSession(record.User, audience)
}

func (s *Store) Authenticate(token string) (Session, error) {
	if token == "" {
		return Session{}, ErrSessionNotFound
	}
	return s.repository.SessionByHash(sha256.Sum256([]byte(token)), s.now().UTC())
}

func (s *Store) Logout(token string) {
	if token == "" {
		return
	}
	_ = s.repository.DeleteSession(sha256.Sum256([]byte(token)))
}

func (s *Store) ListUsers(search string, limit, offset int) (AdminUserPage, error) {
	search = strings.TrimSpace(search)
	if len(search) > 120 {
		return AdminUserPage{}, ErrInvalidInput
	}
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	users, total, err := s.repository.ListUsers(search, limit, offset)
	if err != nil {
		return AdminUserPage{}, err
	}
	return AdminUserPage{Users: users, Total: total, Limit: limit, Offset: offset}, nil
}

// UpdateUserStatus applies an administrator decision to another identity. A
// suspension also invalidates every existing session before the method returns.
func (s *Store) UpdateUserStatus(actorID, userID, status string) error {
	_, err := s.UpdateUserStatusAudited(actorID, userID, status, auditoutbox.Intent{})
	return err
}

// UpdateUserStatusAudited uses the repository transaction as the evidence
// boundary when durable PostgreSQL persistence is configured.
func (s *Store) UpdateUserStatusAudited(actorID, userID, status string, intent auditoutbox.Intent) (bool, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" || (status != "active" && status != "suspended") {
		return false, ErrInvalidInput
	}
	if actorID == userID {
		return false, ErrSelfManagement
	}
	if repository, ok := s.repository.(auditedIdentityRepository); ok && intent.EventID != "" {
		return true, repository.UpdateUserStatusAndDeleteSessionsAudited(userID, status, intent)
	}
	return false, s.repository.UpdateUserStatusAndDeleteSessions(userID, status)
}

func (s *Store) RevokeUserSessions(actorID, userID string) error {
	_, err := s.RevokeUserSessionsAudited(actorID, userID, auditoutbox.Intent{})
	return err
}

func (s *Store) RevokeUserSessionsAudited(actorID, userID string, intent auditoutbox.Intent) (bool, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" || actorID == userID {
		if actorID == userID {
			return false, ErrSelfManagement
		}
		return false, ErrInvalidInput
	}
	if repository, ok := s.repository.(auditedIdentityRepository); ok && intent.EventID != "" {
		return true, repository.DeleteSessionsForUserAudited(userID, intent)
	}
	return false, s.repository.DeleteSessionsForUser(userID)
}

func (s *Store) UserExists(userID string) (bool, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return false, ErrInvalidInput
	}
	return s.repository.UserExists(userID)
}

func (s *Store) UserRole(userID string) (string, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return "", ErrInvalidInput
	}
	return s.repository.UserRole(userID)
}

// GrantRecipient resolves only an active, verified standard-user account.
// Callers deliberately receive ErrUserNotFound for every ineligible state so
// the sharing API does not disclose privileged, suspended, or pending users.
func (s *Store) GrantRecipient(email string) (User, error) {
	email = normalizeEmail(email)
	if !validEmail(email) {
		return User{}, ErrUserNotFound
	}
	record, err := s.repository.UserByEmail(email)
	if err != nil || record.Role != "user" || record.AccountStatus != "active" || record.EmailVerifiedAt == nil {
		return User{}, ErrUserNotFound
	}
	return record.User, nil
}

func (s *Store) createSession(user User, audience string) (User, string, Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return User{}, "", Session{}, err
	}
	csrfToken, err := randomToken(24)
	if err != nil {
		return User{}, "", Session{}, err
	}
	now := s.now().UTC()
	session := Session{User: user, Audience: audience, CSRFToken: csrfToken, ExpiresAt: now.Add(s.sessionTTL)}
	if err := s.repository.CreateSession(sha256.Sum256([]byte(token)), session, now); err != nil {
		return User{}, "", Session{}, err
	}
	return user, token, session, nil
}

func roleAllowedForAudience(role, audience string) bool {
	switch audience {
	case SessionAudienceUser:
		return role == "user"
	case SessionAudiencePrivileged:
		return role == "admin" || role == "auditor"
	default:
		return false
	}
}

func (s *Store) deliverVerification(user User, token string, expiresAt time.Time) error {
	verificationURL := s.publicAppURL + "/#verify-email?token=" + url.QueryEscape(token)
	return s.mailer.SendVerification(VerificationMessage{To: user.Email, Name: user.Name, VerificationURL: verificationURL, ExpiresAt: expiresAt})
}

func normalizeEmail(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func validEmail(value string) bool {
	if len(value) == 0 || len(value) > 254 {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}

func validName(value string) bool {
	return len(value) > 0 && len(value) <= 120 && !strings.ContainsAny(value, "\r\n\x00")
}

func strongPassword(value string) bool {
	if len(value) < 12 || len(value) > 128 {
		return false
	}
	var lower, upper, number, symbol bool
	for _, character := range value {
		switch {
		case unicode.IsLower(character):
			lower = true
		case unicode.IsUpper(character):
			upper = true
		case unicode.IsNumber(character):
			number = true
		default:
			symbol = true
		}
	}
	return lower && upper && number && symbol
}

func passwordMaterial(password string) []byte {
	digest := sha256.Sum256([]byte(password))
	return digest[:]
}

func opaqueID(prefix string) (string, error) {
	value, err := randomToken(12)
	if err != nil {
		return "", err
	}
	return prefix + "_" + value, nil
}

func randomToken(byteCount int) (string, error) {
	buffer := make([]byte, byteCount)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
