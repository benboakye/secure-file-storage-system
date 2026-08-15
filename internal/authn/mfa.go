package authn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // TOTP interoperability requires the RFC 6238 default algorithm.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const mfaChallengeTTL = 5 * time.Minute

type MFAConfiguration struct {
	UserID           string
	SecretCiphertext []byte
	SecretNonce      []byte
	ConfirmedAt      time.Time
	LastCounter      int64
}

type MFAChallengeRecord struct {
	User                    User
	PendingSecretCiphertext []byte
	PendingSecretNonce      []byte
	ExpiresAt               time.Time
}

type MFAChallenge struct {
	MFARequired       bool      `json:"mfaRequired"`
	Mode              string    `json:"mode"`
	ChallengeToken    string    `json:"challengeToken"`
	ExpiresAt         time.Time `json:"expiresAt"`
	ManualEntrySecret string    `json:"manualEntrySecret,omitempty"`
	OTPAuthURI        string    `json:"otpAuthUri,omitempty"`
}

type MFACompletion struct {
	User          User
	Token         string
	Session       Session
	RecoveryCodes []string
}

type MFARepository interface {
	MFAConfiguration(userID string) (MFAConfiguration, error)
	CreateMFAChallenge(tokenHash [32]byte, challenge MFAChallengeRecord, now time.Time) error
	ConsumeMFAChallenge(tokenHash [32]byte, now time.Time) (MFAChallengeRecord, error)
	ConfirmMFA(userID string, secretCiphertext, secretNonce []byte, lastCounter int64, recoveryCodeHashes [][32]byte, now time.Time) error
	AdvanceMFACounter(userID string, counter int64) (bool, error)
	ConsumeMFARecoveryCode(userID string, codeHash [32]byte, now time.Time) (bool, error)
}

func (s *Store) PrivilegedMFARequired() bool { return s.requirePrivilegedMFA }

// BeginPrivilegedLogin verifies the password and privileged role but never
// creates a session. The returned transaction is short-lived and single-use.
func (s *Store) BeginPrivilegedLogin(email, password string) (MFAChallenge, error) {
	if !s.requirePrivilegedMFA {
		return MFAChallenge{}, ErrMFANotConfigured
	}
	record, err := s.verifyCredentials(email, password, SessionAudiencePrivileged)
	if err != nil {
		return MFAChallenge{}, err
	}
	repository, ok := s.repository.(MFARepository)
	if !ok {
		return MFAChallenge{}, errors.New("authentication repository does not support MFA")
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	challengeToken, err := randomToken(32)
	if err != nil {
		return MFAChallenge{}, err
	}
	challenge := MFAChallenge{MFARequired: true, Mode: "challenge", ChallengeToken: challengeToken, ExpiresAt: now.Add(mfaChallengeTTL)}
	stored := MFAChallengeRecord{User: record.User, ExpiresAt: challenge.ExpiresAt}
	if _, err := repository.MFAConfiguration(record.ID); errors.Is(err, ErrMFANotConfigured) {
		secret := make([]byte, 20)
		if _, err := rand.Read(secret); err != nil {
			return MFAChallenge{}, err
		}
		stored.PendingSecretCiphertext, stored.PendingSecretNonce, err = sealMFASecret(s.mfaEncryptionKey, secret)
		if err != nil {
			return MFAChallenge{}, err
		}
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
		challenge.Mode, challenge.ManualEntrySecret = "enroll", encoded
		label := url.PathEscape(s.mfaIssuer + ":" + record.Email)
		query := url.Values{"secret": {encoded}, "issuer": {s.mfaIssuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
		challenge.OTPAuthURI = "otpauth://totp/" + label + "?" + query.Encode()
	} else if err != nil {
		return MFAChallenge{}, err
	}
	if err := repository.CreateMFAChallenge(sha256.Sum256([]byte(challengeToken)), stored, now); err != nil {
		return MFAChallenge{}, err
	}
	return challenge, nil
}

func (s *Store) CompletePrivilegedLogin(challengeToken, code string) (MFACompletion, error) {
	if !s.requirePrivilegedMFA {
		return MFACompletion{}, ErrMFANotConfigured
	}
	if len(strings.TrimSpace(challengeToken)) < 32 {
		return MFACompletion{}, ErrMFAChallenge
	}
	repository := s.repository.(MFARepository)
	now := s.now().UTC().Truncate(time.Microsecond)
	challenge, err := repository.ConsumeMFAChallenge(sha256.Sum256([]byte(strings.TrimSpace(challengeToken))), now)
	if err != nil {
		return MFACompletion{}, err
	}
	currentRecord, err := s.repository.UserByEmail(challenge.User.Email)
	if err != nil || currentRecord.AccountStatus != "active" || (currentRecord.LockedUntil != nil && currentRecord.LockedUntil.After(now)) || !roleAllowedForAudience(currentRecord.Role, SessionAudiencePrivileged) {
		return MFACompletion{}, ErrMFAChallenge
	}
	challenge.User.Role = currentRecord.Role

	configuration, configErr := repository.MFAConfiguration(challenge.User.ID)
	enrolling := len(challenge.PendingSecretCiphertext) > 0
	var ciphertext, nonce []byte
	if enrolling {
		ciphertext, nonce = challenge.PendingSecretCiphertext, challenge.PendingSecretNonce
	} else {
		if configErr != nil {
			return MFACompletion{}, configErr
		}
		ciphertext, nonce = configuration.SecretCiphertext, configuration.SecretNonce
	}
	secret, err := openMFASecret(s.mfaEncryptionKey, ciphertext, nonce)
	if err != nil {
		return MFACompletion{}, ErrMFAInvalid
	}
	defer clear(secret)

	counter, valid := validateTOTP(secret, code, now)
	if !valid && !enrolling {
		valid, err = repository.ConsumeMFARecoveryCode(challenge.User.ID, recoveryCodeHash(challenge.User.ID, code), now)
		if err != nil {
			return MFACompletion{}, err
		}
	}
	if !valid {
		_, _ = s.repository.RecordAuthenticationFailure(challenge.User.ID, now, s.loginFailureWindow, s.loginFailureThreshold, s.accountLockDuration)
		return MFACompletion{}, ErrMFAInvalid
	}

	completion := MFACompletion{User: challenge.User}
	if enrolling {
		completion.RecoveryCodes, err = generateRecoveryCodes(10)
		if err != nil {
			return MFACompletion{}, err
		}
		hashes := make([][32]byte, len(completion.RecoveryCodes))
		for index, recoveryCode := range completion.RecoveryCodes {
			hashes[index] = recoveryCodeHash(challenge.User.ID, recoveryCode)
		}
		if err := repository.ConfirmMFA(challenge.User.ID, ciphertext, nonce, counter, hashes, now); err != nil {
			return MFACompletion{}, err
		}
	} else if counter >= 0 {
		advanced, err := repository.AdvanceMFACounter(challenge.User.ID, counter)
		if err != nil {
			return MFACompletion{}, err
		}
		if !advanced {
			_, _ = s.repository.RecordAuthenticationFailure(challenge.User.ID, now, s.loginFailureWindow, s.loginFailureThreshold, s.accountLockDuration)
			return MFACompletion{}, ErrMFAInvalid
		}
	}
	if err := s.repository.ClearAuthenticationFailures(challenge.User.ID); err != nil {
		return MFACompletion{}, err
	}
	completion.User, completion.Token, completion.Session, err = s.createSession(challenge.User, SessionAudiencePrivileged)
	return completion, err
}

func (s *Store) verifyCredentials(email, password, audience string) (UserRecord, error) {
	email = normalizeEmail(email)
	record, err := s.repository.UserByEmail(email)
	exists := err == nil
	hash := s.dummyHash
	if exists {
		hash = record.PasswordHash
	}
	passwordValid := bcrypt.CompareHashAndPassword(hash, passwordMaterial(password)) == nil
	if !passwordValid || !exists {
		if exists && record.AccountStatus == "active" && (record.LockedUntil == nil || !record.LockedUntil.After(s.now().UTC())) {
			_, _ = s.repository.RecordAuthenticationFailure(record.ID, s.now().UTC(), s.loginFailureWindow, s.loginFailureThreshold, s.accountLockDuration)
		}
		return UserRecord{}, ErrInvalidCredentials
	}
	if record.EmailVerifiedAt == nil {
		return UserRecord{}, ErrEmailNotVerified
	}
	if record.AccountStatus != "active" || (record.LockedUntil != nil && record.LockedUntil.After(s.now().UTC())) || !roleAllowedForAudience(record.Role, audience) {
		return UserRecord{}, ErrInvalidCredentials
	}
	return record, nil
}

func sealMFASecret(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return aead.Seal(nil, nonce, plaintext, []byte("securestore-mfa-v1")), nonce, nil
}
func openMFASecret(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, []byte("securestore-mfa-v1"))
}
func validateTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return -1, false
	}
	provided, err := strconv.Atoi(code)
	if err != nil {
		return -1, false
	}
	current := now.Unix() / 30
	for _, counter := range []int64{current, current - 1, current + 1} {
		expected := totpCode(secret, counter)
		if subtle.ConstantTimeEq(int32(provided), int32(expected)) == 1 {
			return counter, true
		}
	}
	return -1, false
}
func totpCode(secret []byte, counter int64) int {
	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(payload[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	value := (int(sum[offset])&0x7f)<<24 | int(sum[offset+1])<<16 | int(sum[offset+2])<<8 | int(sum[offset+3])
	return value % 1_000_000
}
func recoveryCodeHash(userID, code string) [32]byte {
	return sha256.Sum256([]byte(userID + "\x00" + strings.ToUpper(strings.TrimSpace(code))))
}
func generateRecoveryCodes(count int) ([]string, error) {
	result := make([]string, count)
	for i := range result {
		raw, err := randomToken(6)
		if err != nil {
			return nil, err
		}
		raw = strings.ToUpper(strings.NewReplacer("-", "A", "_", "B").Replace(raw))
		result[i] = fmt.Sprintf("%s-%s", raw[:4], raw[4:8])
	}
	return result, nil
}
