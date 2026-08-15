package authn

import (
	"crypto/sha256"
	"errors"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"securestore/internal/auditoutbox"
)

var ErrInvitationToken = errors.New("privileged invitation is invalid or expired")

type PrivilegedInvitation struct {
	InvitedBy string
	Name      string
	Email     string
	Role      string
	ExpiresAt time.Time
}

type PrivilegedInvitationRepository interface {
	CreatePrivilegedInvitation(tokenHash [32]byte, invitation PrivilegedInvitation, now time.Time) error
	AcceptPrivilegedInvitation(tokenHash [32]byte, record UserRecord, now time.Time) (User, error)
}

type auditedPrivilegedInvitationRepository interface {
	CreatePrivilegedInvitationAudited([32]byte, PrivilegedInvitation, time.Time, auditoutbox.Intent) error
	AcceptPrivilegedInvitationAudited([32]byte, UserRecord, time.Time, auditoutbox.Intent) (User, error)
}

// InvitePrivilegedAccount creates no account and accepts no recipient password.
// The recipient establishes separate credentials through the single-use link.
func (s *Store) InvitePrivilegedAccount(actorID, name, email, role string) error {
	_, err := s.InvitePrivilegedAccountAudited(actorID, name, email, role, auditoutbox.Intent{})
	return err
}

func (s *Store) InvitePrivilegedAccountAudited(actorID, name, email, role string, intent auditoutbox.Intent) (bool, error) {
	name = strings.TrimSpace(name)
	email = normalizeEmail(email)
	if actorID == "" || !validName(name) || !validEmail(email) || (role != "admin" && role != "auditor") {
		return false, ErrInvalidInput
	}
	if _, err := s.repository.UserByEmail(email); err == nil {
		return false, ErrDuplicateUser
	} else if !errors.Is(err, ErrUserNotFound) {
		return false, err
	}
	repository, ok := s.repository.(PrivilegedInvitationRepository)
	if !ok {
		return false, errors.New("authentication repository does not support privileged invitations")
	}
	token, err := randomToken(32)
	if err != nil {
		return false, err
	}
	now := s.now().UTC()
	invitation := PrivilegedInvitation{InvitedBy: actorID, Name: name, Email: email, Role: role, ExpiresAt: now.Add(s.verificationTTL)}
	durable := false
	if audited, ok := s.repository.(auditedPrivilegedInvitationRepository); ok && intent.EventID != "" {
		durable = true
		if err := audited.CreatePrivilegedInvitationAudited(sha256.Sum256([]byte(token)), invitation, now, intent); err != nil {
			return false, err
		}
	} else if err := repository.CreatePrivilegedInvitation(sha256.Sum256([]byte(token)), invitation, now); err != nil {
		return false, err
	}
	activationURL := s.publicAppURL + "/#activate-privileged?token=" + url.QueryEscape(token)
	return durable, s.mailer.SendVerification(VerificationMessage{To: email, Name: name, VerificationURL: activationURL, ExpiresAt: invitation.ExpiresAt})
}

// ActivatePrivilegedAccount consumes the invitation and creates a verified,
// sessionless identity. TOTP enrollment remains mandatory at first sign-in.
func (s *Store) ActivatePrivilegedAccount(token, password string) (User, error) {
	user, _, err := s.ActivatePrivilegedAccountAudited(token, password, auditoutbox.Intent{})
	return user, err
}

func (s *Store) ActivatePrivilegedAccountAudited(token, password string, intent auditoutbox.Intent) (User, bool, error) {
	token = strings.TrimSpace(token)
	if len(token) < 32 || len(token) > 256 || !strongPassword(password) {
		return User{}, false, ErrInvitationToken
	}
	repository, ok := s.repository.(PrivilegedInvitationRepository)
	if !ok {
		return User{}, false, errors.New("authentication repository does not support privileged invitations")
	}
	passwordHash, err := bcrypt.GenerateFromPassword(passwordMaterial(password), passwordHashCost)
	if err != nil {
		return User{}, false, err
	}
	userID, err := opaqueID("usr")
	if err != nil {
		return User{}, false, err
	}
	record := UserRecord{User: User{ID: userID}, PasswordHash: passwordHash, AccountStatus: "active", CreatedAt: s.now().UTC()}
	durable := false
	var created User
	if audited, ok := s.repository.(auditedPrivilegedInvitationRepository); ok && intent.EventID != "" {
		durable = true
		intent.ResourceID = userID
		created, err = audited.AcceptPrivilegedInvitationAudited(sha256.Sum256([]byte(token)), record, s.now().UTC(), intent)
	} else {
		created, err = repository.AcceptPrivilegedInvitation(sha256.Sum256([]byte(token)), record, s.now().UTC())
	}
	if err != nil {
		if errors.Is(err, ErrInvitationToken) || errors.Is(err, ErrDuplicateUser) {
			return User{}, false, ErrInvitationToken
		}
		return User{}, false, err
	}
	return created, durable, nil
}
