package protectedstore

import (
	"errors"
	"strings"
	"time"

	"securestore/internal/auditoutbox"
)

const (
	PermissionRead     = "read"
	PermissionDownload = "download"
)

type Recipient struct {
	ID    string
	Name  string
	Email string
}

type Grant struct {
	GrantID        string     `json:"grantId"`
	FileID         string     `json:"fileId"`
	OwnerID        string     `json:"ownerId"`
	RecipientID    string     `json:"recipientId"`
	RecipientName  string     `json:"recipientName"`
	RecipientEmail string     `json:"recipientEmail"`
	Permission     string     `json:"permission"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
}

type SharedFile struct {
	LogicalFile
	OwnerName  string `json:"ownerName"`
	OwnerEmail string `json:"ownerEmail"`
	Permission string `json:"permission"`
}

type AccessRepository interface {
	CreateGrant(ownerID, fileID string, recipient Recipient, permission string, expiresAt *time.Time) (Grant, error)
	ListGrants(ownerID, fileID string) ([]Grant, error)
	RevokeGrant(ownerID, fileID, grantID string) error
	AuthorizedDetails(requesterID, fileID, capability string) (Details, error)
	AuthorizedCurrentMetadata(requesterID, fileID, capability string) (Metadata, error)
	ListSharedFiles(recipientID string) ([]SharedFile, error)
}

type auditedAccessRepository interface {
	CreateGrantAudited(string, string, Recipient, string, *time.Time, auditoutbox.Intent) (Grant, error)
	RevokeGrantAudited(string, string, string, auditoutbox.Intent) error
}

func (s *Service) ListSharedFiles(recipientID string) ([]SharedFile, error) {
	access, ok := s.repository.(AccessRepository)
	if !ok {
		return nil, errors.New("protected access grants are unavailable")
	}
	return access.ListSharedFiles(recipientID)
}

func validPermission(value string) bool {
	return value == PermissionRead || value == PermissionDownload
}

func (s *Service) CreateGrant(ownerID, fileID string, recipient Recipient, permission string, expiresAt *time.Time) (Grant, error) {
	grant, _, err := s.CreateGrantAudited(ownerID, fileID, recipient, permission, expiresAt, auditoutbox.Intent{})
	return grant, err
}

func (s *Service) CreateGrantAudited(ownerID, fileID string, recipient Recipient, permission string, expiresAt *time.Time, intent auditoutbox.Intent) (Grant, bool, error) {
	access, ok := s.repository.(AccessRepository)
	if !ok {
		return Grant{}, false, errors.New("protected access grants are unavailable")
	}
	permission = strings.ToLower(strings.TrimSpace(permission))
	if !validPermission(permission) || recipient.ID == "" || recipient.ID == ownerID {
		return Grant{}, false, errors.New("invalid access grant")
	}
	if expiresAt != nil && !expiresAt.After(s.now().UTC()) {
		return Grant{}, false, errors.New("grant expiry must be in the future")
	}
	if audited, ok := s.repository.(auditedAccessRepository); ok && intent.EventID != "" {
		grant, err := audited.CreateGrantAudited(ownerID, fileID, recipient, permission, expiresAt, intent)
		return grant, true, err
	}
	grant, err := access.CreateGrant(ownerID, fileID, recipient, permission, expiresAt)
	return grant, false, err
}

func (s *Service) ListGrants(ownerID, fileID string) ([]Grant, error) {
	access, ok := s.repository.(AccessRepository)
	if !ok {
		return nil, errors.New("protected access grants are unavailable")
	}
	return access.ListGrants(ownerID, fileID)
}

func (s *Service) RevokeGrant(ownerID, fileID, grantID string) error {
	_, err := s.RevokeGrantAudited(ownerID, fileID, grantID, auditoutbox.Intent{})
	return err
}

func (s *Service) RevokeGrantAudited(ownerID, fileID, grantID string, intent auditoutbox.Intent) (bool, error) {
	access, ok := s.repository.(AccessRepository)
	if !ok {
		return false, errors.New("protected access grants are unavailable")
	}
	if audited, ok := s.repository.(auditedAccessRepository); ok && intent.EventID != "" {
		return true, audited.RevokeGrantAudited(ownerID, fileID, grantID, intent)
	}
	return false, access.RevokeGrant(ownerID, fileID, grantID)
}

func (s *Service) AuthorizedDetails(requesterID, fileID string) (Details, error) {
	access, ok := s.repository.(AccessRepository)
	if !ok {
		return Details{}, errors.New("protected access grants are unavailable")
	}
	return access.AuthorizedDetails(requesterID, fileID, PermissionRead)
}

func (s *Service) OpenCurrentAuthorized(requesterID, fileID string) (File, error) {
	access, ok := s.repository.(AccessRepository)
	if !ok {
		return File{}, errors.New("protected access grants are unavailable")
	}
	metadata, err := access.AuthorizedCurrentMetadata(requesterID, fileID, PermissionDownload)
	if err != nil {
		return File{}, err
	}
	return s.openMetadata(metadata)
}
