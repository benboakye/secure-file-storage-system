package protectedstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"securestore/internal/auditoutbox"
)

var (
	ErrRetentionActive = errors.New("file retention period is active")
	ErrLegalHold       = errors.New("file is subject to a legal hold")
	ErrNotInTrash      = errors.New("file is not in trash")
	ErrPurgeTooEarly   = errors.New("file deletion grace period is active")
)

const DefaultDeletionGracePeriod = 30 * 24 * time.Hour

type LifecycleFile struct {
	LogicalFile
	DeletedAt       *time.Time `json:"deletedAt,omitempty"`
	PurgeAfter      *time.Time `json:"purgeAfter,omitempty"`
	RetentionUntil  *time.Time `json:"retentionUntil,omitempty"`
	LegalHold       bool       `json:"legalHold"`
	LegalHoldReason string     `json:"legalHoldReason,omitempty"`
	PurgedAt        *time.Time `json:"purgedAt,omitempty"`
}

type LifecycleSummary struct {
	Active             int                 `json:"active"`
	Trashed            int                 `json:"trashed"`
	Retained           int                 `json:"retained"`
	Held               int                 `json:"held"`
	Purged             int                 `json:"purged"`
	EligibleForPurge   int                 `json:"eligibleForPurge"`
	Files              []LifecycleFile     `json:"files"`
	DeletionOperations []DeletionOperation `json:"deletionOperations"`
	RecoveryDrills     []RecoveryDrill     `json:"recoveryDrills"`
	Alerts             []LifecycleAlert    `json:"alerts"`
	Backup             BackupPosture       `json:"backup"`
}

type DeletionOperation struct {
	OperationID   string     `json:"operationId"`
	FileID        string     `json:"fileId"`
	OwnerID       string     `json:"ownerId"`
	Status        string     `json:"status"`
	DestroyedKeys int        `json:"destroyedKeys"`
	Attempts      int        `json:"attempts"`
	ReasonCode    string     `json:"reasonCode"`
	CompletedAt   *time.Time `json:"completedAt,omitempty"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}
type RecoveryDrill struct {
	DrillID     string    `json:"drillId"`
	FileID      string    `json:"fileId"`
	VersionID   string    `json:"versionId"`
	RequestedBy string    `json:"requestedBy"`
	Outcome     string    `json:"outcome"`
	ReasonCode  string    `json:"reasonCode"`
	VerifiedAt  time.Time `json:"verifiedAt"`
}
type LifecycleAlert struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Count    int    `json:"count"`
}
type BackupPosture struct {
	Connected        bool       `json:"connected"`
	ProductionReady  bool       `json:"productionReady"`
	Adapter          string     `json:"adapter"`
	Status           string     `json:"status"`
	Detail           string     `json:"detail"`
	LastSuccessfulAt *time.Time `json:"lastSuccessfulAt,omitempty"`
}

// BackupProvider is deliberately evidence-only at this boundary. A deployment
// adapter must independently create and verify backups, then report its
// observed posture; the storage service never infers backup health from a
// reachable filesystem or from the success of ordinary file operations.
type BackupProvider interface{ Posture() BackupPosture }

type UnconfiguredBackupProvider struct{}

func (UnconfiguredBackupProvider) Posture() BackupPosture {
	return BackupPosture{Connected: false, ProductionReady: false, Adapter: "not_configured", Status: "unavailable", Detail: "No backup provider is configured. Deployment must connect provider evidence before backup health can be asserted."}
}

type WorkerResult struct {
	Examined  int `json:"examined"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

type PurgeResult struct {
	FileID, OperationID string
	DestroyedKeys       int       `json:"destroyedKeys"`
	CompletedAt         time.Time `json:"completedAt"`
	BlobObjects         []string  `json:"-"`
}

type LifecycleRepository interface {
	ListTrash(ownerID string) ([]LifecycleFile, error)
	MoveToTrash(ownerID, fileID string, now, purgeAfter time.Time) (LifecycleFile, error)
	RestoreFromTrash(ownerID, fileID string, now time.Time) (LifecycleFile, error)
	Purge(ownerID, fileID, operationID string, now time.Time) (PurgeResult, error)
	SetRetention(fileID string, until *time.Time) (LifecycleFile, error)
	SetLegalHold(fileID string, enabled bool, reason string) (LifecycleFile, error)
	LifecycleSummary(now time.Time, limit int) (LifecycleSummary, error)
	EligibleForPurge(now time.Time, limit int) ([]LifecycleFile, error)
	RecordDeletionFailure(ownerID, fileID, operationID, reason string, now time.Time) error
	CurrentMetadataForDrill(fileID string) (Metadata, error)
	RecordRecoveryDrill(RecoveryDrill) error
}

type auditedLifecycleRepository interface {
	MoveToTrashAudited(string, string, time.Time, time.Time, auditoutbox.Intent) (LifecycleFile, error)
	RestoreFromTrashAudited(string, string, time.Time, auditoutbox.Intent) (LifecycleFile, error)
	PurgeAudited(string, string, string, time.Time, auditoutbox.Intent) (PurgeResult, error)
	SetRetentionAudited(string, *time.Time, auditoutbox.Intent) (LifecycleFile, error)
	SetLegalHoldAudited(string, bool, string, auditoutbox.Intent) (LifecycleFile, error)
	RecordDeletionFailureAudited(string, string, string, string, time.Time, auditoutbox.Intent) error
	RecordRecoveryDrillAudited(RecoveryDrill, auditoutbox.Intent) error
}

func (s *Service) ListTrash(ownerID string) ([]LifecycleFile, error) {
	return s.lifecycle().ListTrash(ownerID)
}
func (s *Service) MoveToTrash(ownerID, fileID string) (LifecycleFile, error) {
	file, _, err := s.MoveToTrashAudited(ownerID, fileID, auditoutbox.Intent{})
	return file, err
}
func (s *Service) MoveToTrashAudited(ownerID, fileID string, intent auditoutbox.Intent) (LifecycleFile, bool, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	if repository, ok := s.repository.(auditedLifecycleRepository); ok && intent.EventID != "" {
		file, err := repository.MoveToTrashAudited(ownerID, fileID, now, now.Add(DefaultDeletionGracePeriod), intent)
		return file, true, err
	}
	file, err := s.lifecycle().MoveToTrash(ownerID, fileID, now, now.Add(DefaultDeletionGracePeriod))
	return file, false, err
}
func (s *Service) RestoreFromTrash(ownerID, fileID string) (LifecycleFile, error) {
	file, _, err := s.RestoreFromTrashAudited(ownerID, fileID, auditoutbox.Intent{})
	return file, err
}
func (s *Service) RestoreFromTrashAudited(ownerID, fileID string, intent auditoutbox.Intent) (LifecycleFile, bool, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	if repository, ok := s.repository.(auditedLifecycleRepository); ok && intent.EventID != "" {
		file, err := repository.RestoreFromTrashAudited(ownerID, fileID, now, intent)
		return file, true, err
	}
	file, err := s.lifecycle().RestoreFromTrash(ownerID, fileID, now)
	return file, false, err
}
func (s *Service) Purge(ownerID, fileID, idempotencyKey string) (PurgeResult, error) {
	result, _, err := s.PurgeAudited(ownerID, fileID, idempotencyKey, auditoutbox.Intent{})
	return result, err
}

// PurgeOperationIDs binds the deletion tombstone and its audit event to the
// same owner, file, and caller-supplied idempotency key. The digest is opaque
// and lets every layer address one logical deletion across retries.
func PurgeOperationIDs(ownerID, fileID, idempotencyKey string) (operationID, auditEventID string, err error) {
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if len(idempotencyKey) < 8 || len(idempotencyKey) > 128 {
		return "", "", errors.New("invalid purge idempotency key")
	}
	digest := sha256.Sum256([]byte(ownerID + "\x00" + fileID + "\x00" + idempotencyKey))
	encoded := hex.EncodeToString(digest[:])
	return "purge_" + encoded, "aud_purge_" + encoded, nil
}

func (s *Service) PurgeAudited(ownerID, fileID, idempotencyKey string, intent auditoutbox.Intent) (PurgeResult, bool, error) {
	operationID, auditEventID, err := PurgeOperationIDs(ownerID, fileID, idempotencyKey)
	if err != nil {
		return PurgeResult{}, false, err
	}
	if intent.EventID != "" {
		// An HTTP retry must address the same audit fact as the original purge.
		// The digest contains no plaintext identifiers and is already bound to
		// the owner, file, and caller-supplied idempotency key.
		intent.EventID = auditEventID
	}
	durable := false
	var result PurgeResult
	if repository, ok := s.repository.(auditedLifecycleRepository); ok && intent.EventID != "" {
		durable = true
		result, err = repository.PurgeAudited(ownerID, fileID, operationID, s.now().UTC().Truncate(time.Microsecond), intent)
	} else {
		result, err = s.lifecycle().Purge(ownerID, fileID, operationID, s.now().UTC().Truncate(time.Microsecond))
	}
	if err != nil {
		return PurgeResult{}, false, err
	}
	// Key destruction is the security boundary. Ciphertext cleanup is deliberately
	// best-effort because an orphan without its wrapped DEK is unrecoverable.
	for _, object := range result.BlobObjects {
		_ = os.Remove(filepath.Join(s.rootDir, object))
	}
	return result, durable, nil
}
func (s *Service) SetRetention(fileID string, until *time.Time) (LifecycleFile, error) {
	file, _, err := s.SetRetentionAudited(fileID, until, auditoutbox.Intent{})
	return file, err
}
func (s *Service) SetRetentionAudited(fileID string, until *time.Time, intent auditoutbox.Intent) (LifecycleFile, bool, error) {
	if repository, ok := s.repository.(auditedLifecycleRepository); ok && intent.EventID != "" {
		file, err := repository.SetRetentionAudited(fileID, until, intent)
		return file, true, err
	}
	file, err := s.lifecycle().SetRetention(fileID, until)
	return file, false, err
}
func (s *Service) SetLegalHold(fileID string, enabled bool, reason string) (LifecycleFile, error) {
	file, _, err := s.SetLegalHoldAudited(fileID, enabled, reason, auditoutbox.Intent{})
	return file, err
}
func (s *Service) SetLegalHoldAudited(fileID string, enabled bool, reason string, intent auditoutbox.Intent) (LifecycleFile, bool, error) {
	reason = strings.TrimSpace(reason)
	if enabled && (len(reason) < 4 || len(reason) > 160) {
		return LifecycleFile{}, false, errors.New("legal hold reason is required")
	}
	if repository, ok := s.repository.(auditedLifecycleRepository); ok && intent.EventID != "" {
		file, err := repository.SetLegalHoldAudited(fileID, enabled, reason, intent)
		return file, true, err
	}
	file, err := s.lifecycle().SetLegalHold(fileID, enabled, reason)
	return file, false, err
}
func (s *Service) LifecycleSummary(limit int) (LifecycleSummary, error) {
	summary, err := s.lifecycle().LifecycleSummary(s.now().UTC(), limit)
	if err != nil {
		return LifecycleSummary{}, err
	}
	// JSON arrays remain arrays even when there is no evidence yet, which keeps
	// API consumers from treating an empty operational view as missing data.
	if summary.Files == nil {
		summary.Files = []LifecycleFile{}
	}
	if summary.DeletionOperations == nil {
		summary.DeletionOperations = []DeletionOperation{}
	}
	if summary.RecoveryDrills == nil {
		summary.RecoveryDrills = []RecoveryDrill{}
	}
	if summary.Alerts == nil {
		summary.Alerts = []LifecycleAlert{}
	}
	summary.Backup = s.backup.Posture()
	if summary.EligibleForPurge > 0 {
		summary.Alerts = append(summary.Alerts, LifecycleAlert{ID: "purge-eligible", Severity: "medium", Title: "Files awaiting permanent deletion", Detail: "Recovery periods have expired and policy gates permit deletion.", Count: summary.EligibleForPurge})
	}
	failed := 0
	for _, operation := range summary.DeletionOperations {
		if operation.Status == "failed" {
			failed++
		}
	}
	if failed > 0 {
		summary.Alerts = append(summary.Alerts, LifecycleAlert{ID: "deletion-failures", Severity: "high", Title: "Deletion operations require attention", Detail: "One or more cryptographic deletion attempts failed closed and will be retried.", Count: failed})
	}
	return summary, nil
}
func (s *Service) lifecycle() LifecycleRepository { return s.repository.(LifecycleRepository) }

func (s *Service) ProcessDuePurges(limit int) WorkerResult {
	return s.ProcessDuePurgesAudited(limit, "system", "lifecycle-worker", "")
}

// ProcessDuePurgesAudited records each scheduled deletion at the same commit
// point as key destruction. The caller-level summary event remains useful for
// operations, but it is not the authoritative per-file deletion evidence.
func (s *Service) ProcessDuePurgesAudited(limit int, actorType, actorID, correlationID string) WorkerResult {
	now := s.now().UTC().Truncate(time.Microsecond)
	files, err := s.lifecycle().EligibleForPurge(now, limit)
	if err != nil {
		return WorkerResult{Failed: 1}
	}
	result := WorkerResult{Examined: len(files)}
	for _, file := range files {
		key := "scheduled-" + file.FileID + "-" + file.PurgeAfter.UTC().Format(time.RFC3339Nano)
		eventID, idErr := opaqueID("evt")
		if idErr != nil {
			result.Failed++
			continue
		}
		intent := auditoutbox.Intent{EventID: eventID, OccurredAt: now, ActorType: actorType, ActorID: actorID, Action: "FILE_CRYPTOGRAPHICALLY_DELETED", ResourceType: "file", ResourceID: file.FileID, Outcome: "success", ReasonCode: "scheduled_policy_deletion", CorrelationID: correlationID, ToState: "purged"}
		if _, _, err := s.PurgeAudited(file.OwnerID, file.FileID, key, intent); err != nil {
			digest := sha256.Sum256([]byte(file.OwnerID + "\x00" + file.FileID + "\x00" + key))
			reason := lifecycleReason(err)
			intent.Outcome, intent.ReasonCode, intent.ToState = "failed", reason, "deletion_failed"
			if repository, ok := s.repository.(auditedLifecycleRepository); ok {
				_ = repository.RecordDeletionFailureAudited(file.OwnerID, file.FileID, "purge_"+hex.EncodeToString(digest[:]), reason, now, intent)
			} else {
				_ = s.lifecycle().RecordDeletionFailure(file.OwnerID, file.FileID, "purge_"+hex.EncodeToString(digest[:]), reason, now)
			}
			result.Failed++
		} else {
			result.Completed++
		}
	}
	return result
}

func (s *Service) RunRecoveryDrill(fileID, requestedBy string) (RecoveryDrill, error) {
	drill, _, err := s.RunRecoveryDrillAudited(fileID, requestedBy, auditoutbox.Intent{})
	return drill, err
}

func (s *Service) RunRecoveryDrillAudited(fileID, requestedBy string, intent auditoutbox.Intent) (RecoveryDrill, bool, error) {
	metadata, err := s.lifecycle().CurrentMetadataForDrill(fileID)
	if err != nil {
		return RecoveryDrill{}, false, err
	}
	outcome, reason := "verified", "envelope_ciphertext_and_digest_verified"
	var opened File
	opened, err = s.openMetadata(metadata)
	if err == nil {
		clear(opened.Bytes)
	}
	if err != nil {
		outcome, reason = "failed", "integrity_verification_failed"
	}
	id, idErr := opaqueID("drill")
	if idErr != nil {
		return RecoveryDrill{}, false, idErr
	}
	drill := RecoveryDrill{DrillID: id, FileID: fileID, VersionID: metadata.VersionID, RequestedBy: requestedBy, Outcome: outcome, ReasonCode: reason, VerifiedAt: s.now().UTC().Truncate(time.Microsecond)}
	durable := false
	var recordErr error
	if repository, ok := s.repository.(auditedLifecycleRepository); ok && intent.EventID != "" {
		durable = true
		intent.ActorID, intent.ResourceID, intent.Outcome, intent.ReasonCode, intent.ToState = requestedBy, fileID, outcome, reason, outcome
		recordErr = repository.RecordRecoveryDrillAudited(drill, intent)
	} else {
		recordErr = s.lifecycle().RecordRecoveryDrill(drill)
	}
	if recordErr != nil {
		return RecoveryDrill{}, false, recordErr
	}
	if err != nil {
		return drill, durable, ErrIntegrity
	}
	return drill, durable, nil
}
func lifecycleReason(err error) string {
	switch {
	case errors.Is(err, ErrLegalHold):
		return "legal_hold_active"
	case errors.Is(err, ErrRetentionActive):
		return "retention_active"
	case errors.Is(err, ErrPurgeTooEarly):
		return "grace_period_active"
	default:
		return "deletion_failed_closed"
	}
}
