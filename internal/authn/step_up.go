package authn

import (
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

type StepUpRepository interface {
	CreateStepUpProof(tokenHash, sessionHash [32]byte, userID string, expiresAt, now time.Time) error
	StepUpProofValid(tokenHash, sessionHash [32]byte, userID string, now time.Time) (bool, error)
}

type StepUpProof struct {
	Token     string    `json:"stepUpToken"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (s *Store) AdminStepUpRequired() bool { return s.requireAdminStepUp }

// CreateStepUpProof re-verifies both password and a fresh TOTP code. Recovery
// codes intentionally cannot authorize a high-risk administrator mutation.
func (s *Store) CreateStepUpProof(sessionToken string, session Session, password, code string) (StepUpProof, error) {
	if session.Audience != SessionAudiencePrivileged || session.User.Role != "admin" {
		return StepUpProof{}, ErrStepUpRequired
	}
	record, err := s.verifyCredentials(session.User.Email, password, SessionAudiencePrivileged)
	if err != nil || record.ID != session.User.ID {
		return StepUpProof{}, ErrStepUpRequired
	}
	repository, ok := s.repository.(MFARepository)
	if !ok {
		return StepUpProof{}, ErrStepUpRequired
	}
	configuration, err := repository.MFAConfiguration(record.ID)
	if err != nil {
		return StepUpProof{}, ErrStepUpRequired
	}
	secret, err := openMFASecret(s.mfaEncryptionKey, configuration.SecretCiphertext, configuration.SecretNonce)
	if err != nil {
		return StepUpProof{}, ErrStepUpRequired
	}
	defer clear(secret)

	now := s.now().UTC().Truncate(time.Microsecond)
	counter, valid := validateTOTP(secret, code, now)
	if !valid {
		_, _ = s.repository.RecordAuthenticationFailure(record.ID, now, s.loginFailureWindow, s.loginFailureThreshold, s.accountLockDuration)
		return StepUpProof{}, ErrStepUpRequired
	}
	advanced, err := repository.AdvanceMFACounter(record.ID, counter)
	if err != nil {
		return StepUpProof{}, err
	}
	if !advanced {
		_, _ = s.repository.RecordAuthenticationFailure(record.ID, now, s.loginFailureWindow, s.loginFailureThreshold, s.accountLockDuration)
		return StepUpProof{}, ErrStepUpRequired
	}
	if err := s.repository.ClearAuthenticationFailures(record.ID); err != nil {
		return StepUpProof{}, err
	}

	token, err := randomToken(32)
	if err != nil {
		return StepUpProof{}, err
	}
	proof := StepUpProof{Token: token, ExpiresAt: now.Add(s.stepUpTTL)}
	stepRepository, ok := s.repository.(StepUpRepository)
	if !ok {
		return StepUpProof{}, errors.New("authentication repository does not support step-up proofs")
	}
	if err := stepRepository.CreateStepUpProof(
		sha256.Sum256([]byte(token)),
		sha256.Sum256([]byte(sessionToken)),
		record.ID,
		proof.ExpiresAt,
		now,
	); err != nil {
		return StepUpProof{}, err
	}
	return proof, nil
}

func (s *Store) ValidateStepUpProof(sessionToken string, session Session, proofToken string) bool {
	if strings.TrimSpace(proofToken) == "" || sessionToken == "" {
		return false
	}
	repository, ok := s.repository.(StepUpRepository)
	if !ok {
		return false
	}
	valid, err := repository.StepUpProofValid(
		sha256.Sum256([]byte(proofToken)),
		sha256.Sum256([]byte(sessionToken)),
		session.User.ID,
		s.now().UTC(),
	)
	return err == nil && valid
}
