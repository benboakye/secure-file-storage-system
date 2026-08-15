package protectedstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"time"
)

// LocalKeyProvider is a development-only KEK adapter. Production must replace
// it with a managed KMS/HSM implementation without changing envelope callers.
type LocalKeyProvider struct {
	keys        map[string][]byte
	id, version string
}

func NewLocalKeyProvider(key []byte, id, version string) (*LocalKeyProvider, error) {
	if len(key) != 32 || id == "" || version == "" {
		return nil, errors.New("local KEK must contain exactly 32 bytes and have an ID/version")
	}
	return NewLocalKeyringProvider(map[string][]byte{version: key}, id, version)
}

// NewLocalKeyringProvider models version selection and historical unwrap for
// development. Production must implement this contract with KMS/HSM key IDs.
func NewLocalKeyringProvider(keys map[string][]byte, id, currentVersion string) (*LocalKeyProvider, error) {
	if id == "" || currentVersion == "" || len(keys[currentVersion]) != 32 {
		return nil, errors.New("local KEK keyring requires a 32-byte current key and ID/version")
	}
	cloned := make(map[string][]byte, len(keys))
	for version, key := range keys {
		if version == "" || len(key) != 32 {
			return nil, errors.New("every local KEK version must contain exactly 32 bytes")
		}
		cloned[version] = append([]byte(nil), key...)
	}
	return &LocalKeyProvider{keys: cloned, id: id, version: currentVersion}, nil
}

func (p *LocalKeyProvider) ID() string      { return p.id }
func (p *LocalKeyProvider) Version() string { return p.version }

func (p *LocalKeyProvider) Posture() KeyProviderPosture {
	checkedAt := time.Now().UTC()
	return KeyProviderPosture{
		Connected: true, ProductionReady: false, HardwareBacked: false,
		Adapter: "local-file-keyring", Provider: "local-development",
		KeyID: p.id, KeyVersion: p.version, CheckedAt: &checkedAt,
		Detail: "Development file-backed KEK custody is active; production requires a mutually authenticated hardware-backed key service.",
	}
}

func (p *LocalKeyProvider) Wrap(dek []byte) ([]byte, error) {
	aead, err := localAEAD(p.keys[p.version])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, dek, []byte(p.id+"\x00"+p.version))...), nil
}

func (p *LocalKeyProvider) Unwrap(wrapped []byte, id, version string) ([]byte, error) {
	if subtle.ConstantTimeCompare([]byte(id), []byte(p.id)) != 1 {
		return nil, ErrIntegrity
	}
	key, ok := p.keys[version]
	if !ok {
		return nil, ErrIntegrity
	}
	aead, err := localAEAD(key)
	if err != nil || len(wrapped) <= aead.NonceSize() {
		return nil, ErrIntegrity
	}
	dek, err := aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], []byte(id+"\x00"+version))
	if err != nil || len(dek) != 32 {
		clear(dek)
		return nil, ErrIntegrity
	}
	return dek, nil
}

func localAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
