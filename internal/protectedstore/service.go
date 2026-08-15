package protectedstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	schemaVersion = "securestore-envelope-v1"
	algorithm     = "AES-256-GCM"
)

var (
	ErrNotFound        = errors.New("protected file not found")
	ErrIntegrity       = errors.New("protected file integrity verification failed")
	ErrInvalidEnvelope = errors.New("invalid protected-file envelope")
)

type Metadata struct {
	UploadID, VersionID, OwnerID, BlobObject       string
	SchemaVersion, Algorithm, KEKID, KEKVersion    string
	WrappingKEKID, WrappingKEKVersion              string
	WrappedDEK, Nonce                              []byte
	PlaintextSize                                  int64
	PlaintextDigest, MediaType, InspectionRecordID string
	CreatedAt                                      time.Time
}

type Request struct {
	UploadID, OwnerID, PlaintextDigest, MediaType, InspectionRecordID string
	PlaintextSize                                                     int64
}

type File struct {
	Metadata Metadata
	Bytes    []byte
}

type Repository interface {
	Create(Metadata) (Metadata, bool, error)
	FindByUpload(ownerID, uploadID string) (Metadata, error)
	Durable() bool
}

type KeyProvider interface {
	ID() string
	Version() string
	Wrap([]byte) ([]byte, error)
	Unwrap([]byte, string, string) ([]byte, error)
}

// KeyProviderPosture contains only safe control-plane evidence. Provider
// endpoints, certificates, credentials, key material, and wrapped DEKs are
// deliberately excluded from administrator and telemetry surfaces.
type KeyProviderPosture struct {
	Connected       bool       `json:"connected"`
	ProductionReady bool       `json:"productionReady"`
	HardwareBacked  bool       `json:"hardwareBacked"`
	Adapter         string     `json:"adapter"`
	Provider        string     `json:"provider,omitempty"`
	KeyID           string     `json:"keyId"`
	KeyVersion      string     `json:"keyVersion"`
	CheckedAt       *time.Time `json:"checkedAt,omitempty"`
	Detail          string     `json:"detail"`
}

type keyPostureReporter interface {
	Posture() KeyProviderPosture
}

type Config struct {
	RootDir, StagingDir string
	MaxPlaintextBytes   int64
	Repository          Repository
	Keys                KeyProvider
	Backup              BackupProvider
	// Clock is optional and exists for deterministic lifecycle verification.
	// Production callers leave it unset and use the system clock.
	Clock func() time.Time
}

type Service struct {
	rootDir, stagingDir string
	maxPlaintextBytes   int64
	repository          Repository
	keys                KeyProvider
	backup              BackupProvider
	now                 func() time.Time
}

func NewService(config Config) (*Service, error) {
	if config.RootDir == "" || config.MaxPlaintextBytes <= 0 || config.Repository == nil || config.Keys == nil {
		return nil, errors.New("invalid protected-storage configuration")
	}
	if config.StagingDir == "" {
		config.StagingDir = filepath.Join(config.RootDir, ".staging")
	}
	if config.Backup == nil {
		config.Backup = UnconfiguredBackupProvider{}
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	for _, directory := range []string{config.RootDir, config.StagingDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
	}
	return &Service{rootDir: config.RootDir, stagingDir: config.StagingDir, maxPlaintextBytes: config.MaxPlaintextBytes, repository: config.Repository, keys: config.Keys, backup: config.Backup, now: config.Clock}, nil
}

func (s *Service) Durable() bool { return s.repository.Durable() }

func (s *Service) KeyPosture() KeyProviderPosture {
	if reporter, ok := s.keys.(keyPostureReporter); ok {
		return reporter.Posture()
	}
	return KeyProviderPosture{
		Connected: true, ProductionReady: false, Adapter: "configured-key-provider",
		KeyID: s.keys.ID(), KeyVersion: s.keys.Version(),
		Detail: "Key-provider health and custody evidence are unavailable.",
	}
}

// Protect creates one immutable encrypted version. The upload ID is the
// idempotency boundary: restart recovery returns the already-committed version
// instead of generating a second ciphertext or DEK.
func (s *Service) Protect(ctx context.Context, request Request, source io.Reader) (Metadata, error) {
	if existing, err := s.repository.FindByUpload(request.OwnerID, request.UploadID); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Metadata{}, err
	}
	if request.UploadID == "" || request.OwnerID == "" || request.PlaintextSize <= 0 || request.PlaintextSize > s.maxPlaintextBytes || len(request.PlaintextDigest) != sha256.Size*2 || source == nil {
		return Metadata{}, ErrInvalidEnvelope
	}
	plaintext, err := io.ReadAll(io.LimitReader(source, s.maxPlaintextBytes+1))
	if err != nil || int64(len(plaintext)) != request.PlaintextSize || int64(len(plaintext)) > s.maxPlaintextBytes {
		return Metadata{}, ErrIntegrity
	}
	digest := sha256.Sum256(plaintext)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), request.PlaintextDigest) {
		return Metadata{}, ErrIntegrity
	}
	versionID, err := opaqueID("ver")
	if err != nil {
		return Metadata{}, err
	}
	metadata := Metadata{
		UploadID: request.UploadID, VersionID: versionID, OwnerID: request.OwnerID,
		BlobObject: versionID + ".ciphertext", SchemaVersion: schemaVersion, Algorithm: algorithm,
		KEKID: s.keys.ID(), KEKVersion: s.keys.Version(),
		WrappingKEKID: s.keys.ID(), WrappingKEKVersion: s.keys.Version(), PlaintextSize: request.PlaintextSize,
		PlaintextDigest: strings.ToLower(request.PlaintextDigest), MediaType: request.MediaType,
		InspectionRecordID: request.InspectionRecordID, CreatedAt: s.now().UTC().Truncate(time.Microsecond),
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return Metadata{}, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return Metadata{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Metadata{}, err
	}
	metadata.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(metadata.Nonce); err != nil {
		return Metadata{}, err
	}
	metadata.WrappedDEK, err = s.keys.Wrap(dek)
	clear(dek)
	if err != nil {
		return Metadata{}, err
	}
	ciphertext := aead.Seal(nil, metadata.Nonce, plaintext, canonicalAAD(metadata))
	clear(plaintext)
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	finalPath := filepath.Join(s.rootDir, metadata.BlobObject)
	temporary, err := os.CreateTemp(s.stagingDir, "protect-*.tmp")
	if err != nil {
		return Metadata{}, err
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = temporary.Close(); _ = os.Remove(temporaryPath) }
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return Metadata{}, err
	}
	if _, err := temporary.Write(ciphertext); err != nil {
		cleanup()
		return Metadata{}, err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return Metadata{}, err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return Metadata{}, err
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		_ = os.Remove(temporaryPath)
		return Metadata{}, err
	}
	stored, reused, err := s.repository.Create(metadata)
	if err != nil {
		_ = os.Remove(finalPath)
		return Metadata{}, err
	}
	if reused {
		_ = os.Remove(finalPath)
		return stored, nil
	}
	return metadata, nil
}

// Open authenticates the complete bounded ciphertext before returning any
// plaintext bytes, preventing unauthenticated streaming from reaching callers.
func (s *Service) Open(ownerID, uploadID string) (File, error) {
	metadata, err := s.repository.FindByUpload(ownerID, uploadID)
	if err != nil {
		return File{}, err
	}
	return s.openMetadata(metadata)
}

func (s *Service) openMetadata(metadata Metadata) (File, error) {
	if err := validateMetadata(metadata, s.maxPlaintextBytes); err != nil {
		return File{}, err
	}
	ciphertext, err := os.ReadFile(filepath.Join(s.rootDir, metadata.BlobObject))
	if err != nil {
		return File{}, ErrIntegrity
	}
	wrappingID, wrappingVersion := wrappingKeyIdentity(metadata)
	dek, err := s.keys.Unwrap(metadata.WrappedDEK, wrappingID, wrappingVersion)
	if err != nil {
		return File{}, ErrIntegrity
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return File{}, ErrIntegrity
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return File{}, ErrIntegrity
	}
	plaintext, err := aead.Open(nil, metadata.Nonce, ciphertext, canonicalAAD(metadata))
	if err != nil || int64(len(plaintext)) != metadata.PlaintextSize {
		clear(plaintext)
		return File{}, ErrIntegrity
	}
	digest := sha256.Sum256(plaintext)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), metadata.PlaintextDigest) {
		clear(plaintext)
		return File{}, ErrIntegrity
	}
	return File{Metadata: metadata, Bytes: plaintext}, nil
}

// wrappingKeyIdentity deliberately falls back to the immutable envelope key
// identity. The fallback keeps in-memory fixtures and pre-migration records
// readable; durable rows are backfilled by migration 005.
func wrappingKeyIdentity(value Metadata) (string, string) {
	if value.WrappingKEKID == "" || value.WrappingKEKVersion == "" {
		return value.KEKID, value.KEKVersion
	}
	return value.WrappingKEKID, value.WrappingKEKVersion
}

func validateMetadata(value Metadata, maxBytes int64) error {
	if value.UploadID == "" || value.VersionID == "" || value.OwnerID == "" || value.BlobObject != value.VersionID+".ciphertext" || value.SchemaVersion != schemaVersion || value.Algorithm != algorithm || value.PlaintextSize <= 0 || value.PlaintextSize > maxBytes || len(value.PlaintextDigest) != sha256.Size*2 || len(value.Nonce) != 12 || len(value.WrappedDEK) == 0 {
		return ErrInvalidEnvelope
	}
	return nil
}

func canonicalAAD(value Metadata) []byte {
	var output bytes.Buffer
	for _, field := range []string{value.SchemaVersion, value.Algorithm, value.UploadID, value.VersionID, value.OwnerID, value.PlaintextDigest, value.MediaType, value.InspectionRecordID, value.KEKID, value.KEKVersion, value.CreatedAt.UTC().Format(time.RFC3339Nano)} {
		_ = binary.Write(&output, binary.BigEndian, uint32(len(field)))
		_, _ = output.WriteString(field)
	}
	_ = binary.Write(&output, binary.BigEndian, value.PlaintextSize)
	return output.Bytes()
}

func opaqueID(prefix string) (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
