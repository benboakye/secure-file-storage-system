package authn

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

type captureMailer struct{ messages []VerificationMessage }

func (m *captureMailer) SendVerification(message VerificationMessage) error {
	m.messages = append(m.messages, message)
	return nil
}

func TestPrivilegedMFAEnrollmentReplayProtectionAndRecoveryCode(t *testing.T) {
	repository := NewMemoryRepository()
	mailer := &captureMailer{}
	store, err := NewStoreWithConfig(Config{Repository: repository, Mailer: mailer, SessionTTL: time.Hour, RequirePrivilegedMFA: true, MFAEncryptionKey: []byte("0123456789abcdef0123456789abcdef"), MFAIssuer: "SecureStore Test"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 13, 18, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.Register("MFA Admin", "mfa-admin@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEmail(mailer.lastToken(t)); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpdateUserRole("mfa-admin@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}

	challenge, err := store.BeginPrivilegedLogin("mfa-admin@example.edu", "Correct-Horse-9!")
	if err != nil || challenge.Mode != "enroll" || challenge.ManualEntrySecret == "" {
		t.Fatalf("unexpected enrollment: %#v %v", challenge, err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(challenge.ManualEntrySecret)
	if err != nil {
		t.Fatal(err)
	}
	code := fmt.Sprintf("%06d", totpCode(secret, now.Unix()/30))
	completed, err := store.CompletePrivilegedLogin(challenge.ChallengeToken, code)
	if err != nil || completed.Session.Audience != SessionAudiencePrivileged || len(completed.RecoveryCodes) != 10 {
		t.Fatalf("MFA enrollment failed: %#v %v", completed, err)
	}
	if _, err := store.Authenticate(completed.Token); err != nil {
		t.Fatal(err)
	}

	replayChallenge, err := store.BeginPrivilegedLogin("mfa-admin@example.edu", "Correct-Horse-9!")
	if err != nil || replayChallenge.Mode != "challenge" {
		t.Fatal(err)
	}
	if _, err := store.CompletePrivilegedLogin(replayChallenge.ChallengeToken, code); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("TOTP replay accepted: %v", err)
	}

	recoveryChallenge, err := store.BeginPrivilegedLogin("mfa-admin@example.edu", "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompletePrivilegedLogin(recoveryChallenge.ChallengeToken, completed.RecoveryCodes[0]); err != nil {
		t.Fatalf("recovery code rejected: %v", err)
	}
	reusedChallenge, _ := store.BeginPrivilegedLogin("mfa-admin@example.edu", "Correct-Horse-9!")
	if _, err := store.CompletePrivilegedLogin(reusedChallenge.ChallengeToken, completed.RecoveryCodes[0]); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("recovery code reused: %v", err)
	}
	if !store.SecurityPosture().MFAEnforced {
		t.Fatal("security posture did not report enforced privileged MFA")
	}
}

func TestAdministratorStepUpProofRejectsInvalidAndReplayedAuthentication(t *testing.T) {
	repository := NewMemoryRepository()
	mailer := &captureMailer{}
	store, err := NewStoreWithConfig(Config{
		Repository:           repository,
		Mailer:               mailer,
		SessionTTL:           time.Hour,
		RequirePrivilegedMFA: true,
		MFAEncryptionKey:     []byte("0123456789abcdef0123456789abcdef"),
		MFAIssuer:            "SecureStore Test",
		RequireAdminStepUp:   true,
		StepUpTTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 13, 20, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.Register("Step-up Admin", "step-up@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEmail(mailer.lastToken(t)); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpdateUserRole("step-up@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}

	enrollment, err := store.BeginPrivilegedLogin("step-up@example.edu", "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.ManualEntrySecret)
	if err != nil {
		t.Fatal(err)
	}
	firstCode := fmt.Sprintf("%06d", totpCode(secret, now.Unix()/30))
	firstSession, err := store.CompletePrivilegedLogin(enrollment.ChallengeToken, firstCode)
	if err != nil {
		t.Fatal(err)
	}

	// Create a second privileged session to prove that authorization cannot be
	// copied between two browser sessions belonging to the same administrator.
	now = now.Add(30 * time.Second)
	secondChallenge, err := store.BeginPrivilegedLogin("step-up@example.edu", "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	secondCode := fmt.Sprintf("%06d", totpCode(secret, now.Unix()/30))
	secondSession, err := store.CompletePrivilegedLogin(secondChallenge.ChallengeToken, secondCode)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(30 * time.Second)
	stepUpCode := fmt.Sprintf("%06d", totpCode(secret, now.Unix()/30))
	incorrectCode := fmt.Sprintf("%06d", (totpCode(secret, now.Unix()/30)+1)%1_000_000)
	if _, err := store.CreateStepUpProof(firstSession.Token, firstSession.Session, "Incorrect-Pass-9!", stepUpCode); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("incorrect step-up password was accepted: %v", err)
	}
	if _, err := store.CreateStepUpProof(firstSession.Token, firstSession.Session, "Correct-Horse-9!", incorrectCode); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("incorrect step-up TOTP was accepted: %v", err)
	}
	proof, err := store.CreateStepUpProof(firstSession.Token, firstSession.Session, "Correct-Horse-9!", stepUpCode)
	if err != nil {
		t.Fatal(err)
	}
	// The TOTP counter advances when the proof is issued. Reusing that code must
	// fail even though the password and privileged session remain valid.
	if _, err := store.CreateStepUpProof(firstSession.Token, firstSession.Session, "Correct-Horse-9!", stepUpCode); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("replayed step-up TOTP was accepted: %v", err)
	}
	if !store.ValidateStepUpProof(firstSession.Token, firstSession.Session, proof.Token) {
		t.Fatal("valid step-up proof was rejected for its originating session")
	}
	if store.ValidateStepUpProof(secondSession.Token, secondSession.Session, proof.Token) {
		t.Fatal("step-up proof was accepted by a different privileged session")
	}

	now = proof.ExpiresAt.Add(time.Second)
	if store.ValidateStepUpProof(firstSession.Token, firstSession.Session, proof.Token) {
		t.Fatal("expired step-up proof was accepted")
	}
	if !store.SecurityPosture().AdminStepUpEnforced {
		t.Fatal("security posture did not report enforced administrator step-up")
	}
}

func TestPrivilegedInvitationCreatesSeparateSessionlessIdentity(t *testing.T) {
	repository := NewMemoryRepository()
	mailer := &captureMailer{}
	store, err := NewStoreWithConfig(Config{Repository: repository, Mailer: mailer, VerificationTTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 13, 21, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.Register("Provisioning Admin", "provisioner@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEmail(mailer.lastToken(t)); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpdateUserRole("provisioner@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}
	actor, err := repository.UserByEmail("provisioner@example.edu")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InvitePrivilegedAccount(actor.ID, "Security Auditor", "auditor@example.edu", "auditor"); err != nil {
		t.Fatal(err)
	}
	invitationToken := mailer.lastToken(t)
	created, err := store.ActivatePrivilegedAccount(invitationToken, "Independent-Pass-8!")
	if err != nil {
		t.Fatal(err)
	}
	if created.Role != "auditor" || created.Email != "auditor@example.edu" {
		t.Fatalf("unexpected privileged identity: %#v", created)
	}
	if len(repository.sessionsByHash) != 0 {
		t.Fatal("activation unexpectedly created a session")
	}
	if _, err := store.ActivatePrivilegedAccount(invitationToken, "Independent-Pass-8!"); !errors.Is(err, ErrInvitationToken) {
		t.Fatalf("single-use invitation was accepted twice: %v", err)
	}
	if _, _, _, err := store.Login("auditor@example.edu", "Independent-Pass-8!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("privileged identity crossed into the standard login boundary: %v", err)
	}
}

func TestRepeatedPasswordFailuresTemporarilyLockAccount(t *testing.T) {
	store, mailer := newVerificationStore(t)
	now := time.Date(2026, 8, 13, 19, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.Register("Lockout User", "lockout@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEmail(mailer.lastToken(t)); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		if _, _, _, err := store.Login("lockout@example.edu", "Wrong-Password-9!"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if _, _, _, err := store.Login("lockout@example.edu", "Correct-Horse-9!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("locked account authenticated: %v", err)
	}
	record := store.repository.(*MemoryRepository).usersByEmail["lockout@example.edu"]
	if record.LockedUntil == nil {
		t.Fatal("lockout evidence missing")
	}
	now = now.Add(16 * time.Minute)
	if _, _, _, err := store.Login("lockout@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatalf("account did not unlock after policy duration: %v", err)
	}
}

func (m *captureMailer) lastToken(t *testing.T) string {
	t.Helper()
	if len(m.messages) == 0 {
		t.Fatal("expected a verification message")
	}
	parsed, err := url.Parse(m.messages[len(m.messages)-1].VerificationURL)
	if err != nil {
		t.Fatal(err)
	}
	question := strings.Index(parsed.Fragment, "?")
	if question < 0 {
		t.Fatal("verification URL did not contain a query")
	}
	values, err := url.ParseQuery(parsed.Fragment[question+1:])
	if err != nil {
		t.Fatal(err)
	}
	token := values.Get("token")
	if token == "" {
		t.Fatal("verification message did not contain a token")
	}
	return token
}

func newVerificationStore(t *testing.T) (*Store, *captureMailer) {
	t.Helper()
	mailer := &captureMailer{}
	store, err := NewStoreWithConfig(Config{
		Repository: NewMemoryRepository(), Mailer: mailer, SessionTTL: time.Hour,
		VerificationTTL: 30 * time.Minute, VerificationMinResend: time.Minute,
		PublicAppURL: "http://test.local",
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, mailer
}

func TestRegistrationRequiresVerificationBeforeManualLogin(t *testing.T) {
	store, mailer := newVerificationStore(t)
	if err := store.Register("Jane Student", "JANE@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Login("jane@example.edu", "Correct-Horse-9!"); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("unverified account was not blocked: %v", err)
	}
	token := mailer.lastToken(t)
	if err := store.VerifyEmail(token); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEmail(token); !errors.Is(err, ErrVerificationToken) {
		t.Fatalf("single-use token was accepted twice: %v", err)
	}
	user, loginToken, session, err := store.Login("jane@example.edu", "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "jane@example.edu" || loginToken == "" || session.CSRFToken == "" {
		t.Fatalf("unexpected login result: %#v", user)
	}
	if _, err := store.Authenticate(loginToken); err != nil {
		t.Fatalf("session should authenticate: %v", err)
	}
	store.Logout(loginToken)
	if _, err := store.Authenticate(loginToken); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("logged-out token remained valid: %v", err)
	}
}

func TestStandardAndPrivilegedLoginAudiencesRemainSeparate(t *testing.T) {
	store, mailer := newVerificationStore(t)
	if err := store.Register("Jane Student", "jane@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEmail(mailer.lastToken(t)); err != nil {
		t.Fatal(err)
	}

	_, standardToken, standardSession, err := store.Login("jane@example.edu", "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	if standardSession.Audience != SessionAudienceUser {
		t.Fatalf("unexpected standard session audience: %q", standardSession.Audience)
	}

	repository := store.repository.(*MemoryRepository)
	if err := repository.UpdateUserRole("jane@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(standardToken); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("role change did not revoke the existing session: %v", err)
	}
	if _, _, _, err := store.Login("jane@example.edu", "Correct-Horse-9!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("privileged account entered through standard login: %v", err)
	}

	_, _, privilegedSession, err := store.LoginPrivileged("jane@example.edu", "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	if privilegedSession.Audience != SessionAudiencePrivileged || privilegedSession.User.Role != "admin" {
		t.Fatalf("unexpected privileged session: %#v", privilegedSession)
	}
}

func TestAccountSuspensionRevokesSessionsAndBlocksLogin(t *testing.T) {
	store, mailer := newVerificationStore(t)
	if err := store.Register("Primary Admin", "admin@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEmail(mailer.lastToken(t)); err != nil {
		t.Fatal(err)
	}
	if err := store.Register("Standard User", "user@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEmail(mailer.lastToken(t)); err != nil {
		t.Fatal(err)
	}

	repository := store.repository.(*MemoryRepository)
	if err := repository.UpdateUserRole("admin@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}
	adminRecord, err := repository.UserByEmail("admin@example.edu")
	if err != nil {
		t.Fatal(err)
	}
	userRecord, err := repository.UserByEmail("user@example.edu")
	if err != nil {
		t.Fatal(err)
	}
	_, userToken, _, err := store.Login("user@example.edu", "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}

	if err := store.UpdateUserStatus(adminRecord.ID, userRecord.ID, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(userToken); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("suspension did not invalidate the existing session: %v", err)
	}
	if _, _, _, err := store.Login("user@example.edu", "Correct-Horse-9!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("suspended account did not receive a generic login denial: %v", err)
	}
	page, err := store.ListUsers("user@example.edu", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Users) != 1 || page.Users[0].AccountStatus != "suspended" {
		t.Fatalf("directory did not expose the safe account status: %#v", page)
	}
	if err := store.UpdateUserStatus(adminRecord.ID, userRecord.ID, "active"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Login("user@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatalf("reactivated account could not sign in: %v", err)
	}
	if err := store.UpdateUserStatus(adminRecord.ID, adminRecord.ID, "suspended"); !errors.Is(err, ErrSelfManagement) {
		t.Fatalf("administrator was allowed to suspend the current identity: %v", err)
	}
	if err := store.RevokeUserSessions(adminRecord.ID, adminRecord.ID); !errors.Is(err, ErrSelfManagement) {
		t.Fatalf("administrator was allowed to revoke the current session: %v", err)
	}
	if err := store.UpdateUserStatus(adminRecord.ID, userRecord.ID, "locked"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("manual control accepted the reserved locked state: %v", err)
	}
}

func TestRegistrationPolicyGenericDuplicateAndLongPassword(t *testing.T) {
	store, mailer := newVerificationStore(t)
	if err := store.Register("Jane", "jane@example.edu", "too-weak"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("weak password was accepted: %v", err)
	}
	if err := store.Register("Jane", "jane@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if err := store.Register("Jane", "jane@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatalf("duplicate registration leaked a distinct failure: %v", err)
	}
	if len(mailer.messages) != 1 {
		t.Fatalf("duplicate registration unexpectedly sent mail: %d", len(mailer.messages))
	}
	if _, _, _, err := store.Login("missing@example.edu", "Correct-Horse-9!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("missing user should return generic credentials error: %v", err)
	}
	longPassword := "A1!" + strings.Repeat("secure", 15)
	if err := store.Register("Long Password", "long@example.edu", longPassword); err != nil {
		t.Fatalf("valid long password should be pre-hashed: %v", err)
	}
	if err := store.VerifyEmail(mailer.lastToken(t)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Login("long@example.edu", longPassword); err != nil {
		t.Fatalf("long password login failed: %v", err)
	}
}

func TestVerificationExpiryAndResendThrottle(t *testing.T) {
	store, mailer := newVerificationStore(t)
	current := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return current }
	if err := store.Register("Jane", "jane@example.edu", "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	original := mailer.lastToken(t)
	if err := store.ResendVerification("jane@example.edu"); err != nil {
		t.Fatal(err)
	}
	if len(mailer.messages) != 1 {
		t.Fatal("resend throttle did not suppress immediate request")
	}
	current = current.Add(2 * time.Minute)
	if err := store.ResendVerification("jane@example.edu"); err != nil {
		t.Fatal(err)
	}
	if len(mailer.messages) != 2 {
		t.Fatal("eligible resend did not send a new token")
	}
	if err := store.VerifyEmail(original); !errors.Is(err, ErrVerificationToken) {
		t.Fatalf("replaced token remained valid: %v", err)
	}
	current = current.Add(31 * time.Minute)
	if err := store.VerifyEmail(mailer.lastToken(t)); !errors.Is(err, ErrVerificationToken) {
		t.Fatalf("expired token was accepted: %v", err)
	}
}
