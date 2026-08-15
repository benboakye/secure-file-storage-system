package protectedstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"securestore/internal/auditoutbox"
)

type LogicalFile struct {
	FileID           string    `json:"fileId"`
	OwnerID          string    `json:"ownerId"`
	Name             string    `json:"name"`
	CurrentVersionID string    `json:"currentVersionId"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type Version struct {
	FileID          string    `json:"fileId"`
	VersionID       string    `json:"versionId"`
	SourceVersionID string    `json:"sourceVersionId,omitempty"`
	OperationID     string    `json:"-"`
	Number          int64     `json:"number"`
	PlaintextSize   int64     `json:"plaintextSize"`
	MediaType       string    `json:"mediaType"`
	Reason          string    `json:"reason"`
	Current         bool      `json:"current"`
	CreatedAt       time.Time `json:"createdAt"`
}

type Details struct {
	File     LogicalFile `json:"file"`
	Versions []Version   `json:"versions"`
	Access   string      `json:"access"`
}

type CatalogRepository interface {
	RegisterInitial(ownerID, name string, metadata Metadata) (LogicalFile, Version, error)
	ListFiles(ownerID string) ([]LogicalFile, error)
	Details(ownerID, fileID string) (Details, error)
	CommitRestore(ownerID, fileID, sourceVersionID string, metadata Metadata) (Version, error)
	FindVersion(ownerID, fileID, versionID string) (Metadata, error)
}

type auditedCatalogRepository interface {
	CommitRestoreAudited(string, string, string, Metadata, auditoutbox.Intent) (Version, error)
}

func (s *Service) RegisterInitial(ownerID, name string, metadata Metadata) (LogicalFile, Version, error) {
	catalog, ok := s.repository.(CatalogRepository)
	if !ok {
		return LogicalFile{}, Version{}, errors.New("protected catalog is unavailable")
	}
	return catalog.RegisterInitial(ownerID, name, metadata)
}

func (s *Service) ListFiles(ownerID string) ([]LogicalFile, error) {
	catalog, ok := s.repository.(CatalogRepository)
	if !ok {
		return nil, errors.New("protected catalog is unavailable")
	}
	return catalog.ListFiles(ownerID)
}

func (s *Service) Details(ownerID, fileID string) (Details, error) {
	catalog, ok := s.repository.(CatalogRepository)
	if !ok {
		return Details{}, errors.New("protected catalog is unavailable")
	}
	return catalog.Details(ownerID, fileID)
}

// OpenCurrent resolves the logical file's current immutable version and then
// applies the same authenticated-decryption checks as an upload download.
func (s *Service) OpenCurrent(ownerID, fileID string) (File, error) {
	details, err := s.Details(ownerID, fileID)
	if err != nil {
		return File{}, err
	}
	catalog := s.repository.(CatalogRepository)
	metadata, err := catalog.FindVersion(ownerID, fileID, details.File.CurrentVersionID)
	if err != nil {
		return File{}, err
	}
	return s.openMetadata(metadata)
}

// Restore authenticates the selected immutable source and writes a newly
// encrypted version. It never changes or reuses the source ciphertext.
func (s *Service) Restore(ctx context.Context, ownerID, fileID, sourceVersionID, idempotencyKey string) (Version, error) {
	version, _, err := s.RestoreAudited(ctx, ownerID, fileID, sourceVersionID, idempotencyKey, auditoutbox.Intent{})
	return version, err
}

func (s *Service) RestoreAudited(ctx context.Context, ownerID, fileID, sourceVersionID, idempotencyKey string, intent auditoutbox.Intent) (Version, bool, error) {
	catalog, ok := s.repository.(CatalogRepository)
	if !ok {
		return Version{}, false, errors.New("protected catalog is unavailable")
	}
	sourceMetadata, err := catalog.FindVersion(ownerID, fileID, sourceVersionID)
	if err != nil {
		return Version{}, false, err
	}
	source, err := s.openMetadata(sourceMetadata)
	if err != nil {
		return Version{}, false, err
	}
	defer clear(source.Bytes)
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if len(idempotencyKey) < 8 || len(idempotencyKey) > 128 {
		return Version{}, false, errors.New("invalid restore idempotency key")
	}
	// The key is never stored verbatim. Binding it to the owner, file and source
	// makes retries deterministic without allowing reuse across restore targets.
	digest := sha256.Sum256([]byte(ownerID + "\x00" + fileID + "\x00" + sourceVersionID + "\x00" + idempotencyKey))
	operationID := "restore_" + hex.EncodeToString(digest[:])
	metadata, err := s.Protect(ctx, Request{UploadID: operationID, OwnerID: ownerID, PlaintextSize: sourceMetadata.PlaintextSize, PlaintextDigest: sourceMetadata.PlaintextDigest, MediaType: sourceMetadata.MediaType, InspectionRecordID: sourceMetadata.InspectionRecordID}, bytes.NewReader(source.Bytes))
	if err != nil {
		return Version{}, false, err
	}
	if audited, ok := s.repository.(auditedCatalogRepository); ok && intent.EventID != "" {
		version, err := audited.CommitRestoreAudited(ownerID, fileID, sourceVersionID, metadata, intent)
		return version, true, err
	}
	version, err := catalog.CommitRestore(ownerID, fileID, sourceVersionID, metadata)
	return version, false, err
}
