package ingest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"securestore/internal/auditoutbox"
	"securestore/internal/orphan"

	"securestore/internal/protectedstore"
)

var (
	ErrTooLarge         = errors.New("upload exceeds configured limit")
	ErrQuotaExceeded    = errors.New("owner storage quota exceeded")
	ErrCapacityExceeded = errors.New("protected storage capacity exceeded")
	ErrInvalidFile      = errors.New("invalid upload")
	ErrInvalidKey       = errors.New("invalid idempotency key")
	ErrInvalidQuery     = errors.New("invalid resource query")
	ErrNotFound         = errors.New("upload not found")
	ErrScannerFailure   = errors.New("scanner unavailable")
)

type Status string

const (
	StatusQuarantined Status = "quarantined"
	StatusInspecting  Status = "inspecting"
	StatusAccepted    Status = "accepted"
	StatusEncrypting  Status = "encrypting"
	StatusStored      Status = "stored"
	StatusRejected    Status = "rejected"
	StatusFailed      Status = "failed"
)

type Upload struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Size              int64     `json:"size"`
	DeclaredMediaType string    `json:"declaredMediaType"`
	DetectedMediaType string    `json:"detectedMediaType"`
	Status            Status    `json:"status"`
	Progress          int       `json:"progress"`
	DecisionReason    string    `json:"decisionReason,omitempty"`
	CorrelationID     string    `json:"correlationId"`
	CreatedAt         time.Time `json:"createdAt"`
}

func (m *Manager) OrphanCandidates(minimumAge time.Duration) ([]orphan.Candidate, error) {
	m.mu.RLock()
	tracked := make(map[string]struct{}, len(m.uploads))
	for _, entry := range m.uploads {
		tracked[entry.QuarantineObject] = struct{}{}
	}
	now := m.now().UTC()
	m.mu.RUnlock()
	return orphan.List(m.quarantineDir, "quarantine", tracked, minimumAge, now)
}

func (m *Manager) DeleteOrphan(token string, minimumAge time.Duration) (orphan.Candidate, error) {
	// Registration of a new quarantine object holds the same mutex, so the
	// tracked set cannot change between this revalidation and removal.
	m.mu.Lock()
	defer m.mu.Unlock()
	tracked := make(map[string]struct{}, len(m.uploads))
	for _, entry := range m.uploads {
		tracked[entry.QuarantineObject] = struct{}{}
	}
	return orphan.Delete(m.quarantineDir, "quarantine", tracked, token, minimumAge, m.now().UTC(), nil)
}

// ResumeOrphanReconciliation finishes a deletion already authorized in the
// durable journal. The manager lock prevents an upload from registering the
// same quarantine object while the final tracked-state check and removal run.
func (m *Manager) ResumeOrphanReconciliation(operation protectedstore.OrphanReconciliationOperation) (orphan.ResumeOutcome, error) {
	if operation.Zone != "quarantine" {
		return orphan.ResumeOutcome{}, ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tracked := make(map[string]struct{}, len(m.uploads))
	for _, entry := range m.uploads {
		tracked[entry.QuarantineObject] = struct{}{}
	}
	return orphan.Resume(m.quarantineDir, operation.StorageObject, operation.Size, operation.ModifiedAt, func(object string) (bool, error) {
		_, exists := tracked[object]
		return exists, nil
	})
}

// AdminResource is the deliberately limited metadata projection available to
// privileged operators. It excludes quarantine paths, content digests, file
// bytes, and any future encryption-key material.
type AdminResource struct {
	ID                string    `json:"id"`
	OwnerID           string    `json:"ownerId"`
	Name              string    `json:"name"`
	Size              int64     `json:"size"`
	DeclaredMediaType string    `json:"declaredMediaType"`
	DetectedMediaType string    `json:"detectedMediaType"`
	Status            Status    `json:"status"`
	DecisionReason    string    `json:"decisionReason,omitempty"`
	CorrelationID     string    `json:"correlationId"`
	CreatedAt         time.Time `json:"createdAt"`
}

type AdminResourceSummary struct {
	TrackedUploads        int                      `json:"trackedUploads"`
	TrackedBytes          int64                    `json:"trackedBytes"`
	QuarantineBytes       int64                    `json:"quarantineBytes"`
	OrphanedObjects       int                      `json:"orphanedObjects"`
	OrphanedBytes         int64                    `json:"orphanedBytes"`
	PendingProcessing     int                      `json:"pendingProcessing"`
	BytesLast24Hours      int64                    `json:"bytesLast24Hours"`
	BytesLast7Days        int64                    `json:"bytesLast7Days"`
	OwnerUsage            []OwnerUsage             `json:"ownerUsage"`
	DefaultQuotaBytes     int64                    `json:"defaultQuotaBytes"`
	QuotaAlerts           int                      `json:"quotaAlerts"`
	QuotaOverrides        []QuotaOverride          `json:"quotaOverrides"`
	StatusCounts          map[Status]int           `json:"statusCounts"`
	MetadataDurable       bool                     `json:"metadataDurable"`
	RuntimeOnly           bool                     `json:"runtimeOnly"`
	ProtectedConnected    bool                     `json:"protectedStorageConnected"`
	ProtectedCapacity     ProtectedCapacitySummary `json:"protectedCapacity"`
	StorageCapacityBytes  int64                    `json:"storageCapacityBytes"`
	StorageReserveBytes   int64                    `json:"storageReserveBytes"`
	ReservedCapacityBytes int64                    `json:"reservedCapacityBytes"`
	ActiveReservations    int                      `json:"activeReservations"`
}

// ProtectedCapacitySummary is populated by the API from the protected-storage
// service so ingestion stays independent from encryption and filesystem code.
type ProtectedCapacitySummary struct {
	TrackedObjects         int                      `json:"trackedObjects"`
	TrackedCiphertextBytes int64                    `json:"trackedCiphertextBytes"`
	OrphanedObjects        int                      `json:"orphanedObjects"`
	OrphanedBytes          int64                    `json:"orphanedBytes"`
	MissingObjects         int                      `json:"missingObjects"`
	VolumeTotalBytes       uint64                   `json:"volumeTotalBytes"`
	VolumeAvailableBytes   uint64                   `json:"volumeAvailableBytes"`
	VolumeUsedPercent      float64                  `json:"volumeUsedPercent"`
	Alerts                 []ProtectedCapacityAlert `json:"alerts"`
}

type ProtectedCapacityAlert struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Count    int    `json:"count"`
}

type OwnerUsage struct {
	OwnerID    string `json:"ownerId"`
	Uploads    int    `json:"uploads"`
	Bytes      int64  `json:"bytes"`
	QuotaBytes int64  `json:"quotaBytes"`
}

type QuotaOverride struct {
	OwnerID    string `json:"ownerId"`
	QuotaBytes int64  `json:"quotaBytes"`
}

type AdminResourcePage struct {
	Resources []AdminResource      `json:"resources"`
	Summary   AdminResourceSummary `json:"summary"`
	Total     int                  `json:"total"`
	Limit     int                  `json:"limit"`
	Offset    int                  `json:"offset"`
}

type record struct {
	Upload
	OwnerID          string
	QuarantinePath   string
	QuarantineObject string
	Digest           string
	IdempotencyHash  string
}

type Evidence struct {
	Name              string
	Digest            string
	DetectedMediaType string
	// QuarantinePath is an opaque server-controlled path. Scanner adapters may
	// read it, but must never return it through results, logs, or API posture.
	QuarantinePath string
}

type ScanResult struct {
	Accepted bool
	Reason   string
	Tool     string
	Policy   string
}

type Scanner interface {
	Inspect(context.Context, Evidence) (ScanResult, error)
}

type ScannerPosture struct {
	Connected              bool       `json:"connected"`
	ProductionReady        bool       `json:"productionReady"`
	FailClosed             bool       `json:"failClosed"`
	SignaturesFresh        bool       `json:"signaturesFresh"`
	Adapter                string     `json:"adapter"`
	PolicyVersion          string     `json:"policyVersion"`
	EngineVersion          string     `json:"engineVersion,omitempty"`
	SignatureDB            string     `json:"signatureDatabase,omitempty"`
	SignatureUpdatedAt     *time.Time `json:"signatureUpdatedAt,omitempty"`
	SignatureAgeSeconds    int64      `json:"signatureAgeSeconds,omitempty"`
	SignatureMaxAgeSeconds int64      `json:"signatureMaxAgeSeconds,omitempty"`
	CheckedAt              *time.Time `json:"checkedAt,omitempty"`
	Detail                 string     `json:"detail"`
}

type LifecycleEvent struct {
	OwnerID, UploadID, Action, Outcome, ReasonCode, CorrelationID string
	FromState, ToState                                            Status
}

type PolicyPosture struct {
	MaxUploadBytes         int64 `json:"maxUploadBytes"`
	DefaultOwnerQuotaBytes int64 `json:"defaultOwnerQuotaBytes"`
	InspectionTTLSeconds   int64 `json:"inspectionTtlSeconds"`
	StorageCapacityBytes   int64 `json:"storageCapacityBytes"`
	StorageReserveBytes    int64 `json:"storageReserveBytes"`
	ReservationTTLSeconds  int64 `json:"reservationTtlSeconds"`
}

type LifecyclePosture struct {
	StatusCounts      map[Status]int  `json:"statusCounts"`
	PendingProcessing int             `json:"pendingProcessing"`
	StuckProcessing   int             `json:"stuckProcessing"`
	OldestPendingAt   *time.Time      `json:"oldestPendingAt,omitempty"`
	TrackedRecords    int             `json:"trackedRecords"`
	MetadataDurable   bool            `json:"metadataDurable"`
	QuarantineBytes   int64           `json:"quarantineBytes"`
	OrphanedObjects   int             `json:"orphanedObjects"`
	OrphanedBytes     int64           `json:"orphanedBytes"`
	RecentRecords     []AdminResource `json:"recentRecords"`
}

type scannerPostureReporter interface {
	Posture() ScannerPosture
}

type Config struct {
	QuarantineDir          string
	MaxUploadBytes         int64
	InspectionTTL          time.Duration
	TransitionDelay        time.Duration
	Scanner                Scanner
	Repository             Repository
	DefaultOwnerQuotaBytes int64
	StorageCapacityBytes   int64
	StorageReserveBytes    int64
	ReservationTTL         time.Duration
	ProtectedStore         *protectedstore.Service
	PrepareLifecycleAudit  func(LifecycleEvent) (auditoutbox.Intent, error)
	DeliverLifecycleAudit  func(auditoutbox.Intent, bool)
}

type Manager struct {
	mu                     sync.RWMutex
	uploads                map[string]*record
	idempotency            map[string]string
	quarantineDir          string
	maxUploadBytes         int64
	inspectionTTL          time.Duration
	transitionDelay        time.Duration
	scanner                Scanner
	repository             Repository
	defaultOwnerQuotaBytes int64
	storageCapacityBytes   int64
	storageReserveBytes    int64
	reservationTTL         time.Duration
	ownerReservations      map[string]int64
	ownerQuotas            map[string]int64
	protectedStore         *protectedstore.Service
	now                    func() time.Time
	prepareLifecycleAudit  func(LifecycleEvent) (auditoutbox.Intent, error)
	deliverLifecycleAudit  func(auditoutbox.Intent, bool)
}

// ScannerPosture reports adapter capability, not a simulated health signal.
// Unknown scanners remain connected but are never assumed production-ready.
func (m *Manager) ScannerPosture() ScannerPosture {
	if reporter, ok := m.scanner.(scannerPostureReporter); ok {
		return reporter.Posture()
	}
	return ScannerPosture{Connected: m.scanner != nil, ProductionReady: false, Adapter: "configured-adapter", Detail: "Scanner health reporting is not available."}
}

func (m *Manager) PolicyPosture() PolicyPosture {
	return PolicyPosture{
		MaxUploadBytes: m.maxUploadBytes, DefaultOwnerQuotaBytes: m.defaultOwnerQuotaBytes,
		InspectionTTLSeconds: int64(m.inspectionTTL.Seconds()), StorageCapacityBytes: m.storageCapacityBytes,
		StorageReserveBytes: m.storageReserveBytes, ReservationTTLSeconds: int64(m.reservationTTL.Seconds()),
	}
}

// LifecyclePosture derives workflow evidence from authoritative manager state
// and measured quarantine data. "Stuck" means a non-terminal record older
// than twice the configured inspection deadline; it is an operational signal,
// not an assertion that recovery or retention services exist.
func (m *Manager) LifecyclePosture() (LifecyclePosture, error) {
	page, err := m.ListAdminResources("", 8, 0)
	if err != nil {
		return LifecyclePosture{}, err
	}
	posture := LifecyclePosture{
		StatusCounts: page.Summary.StatusCounts, PendingProcessing: page.Summary.PendingProcessing,
		TrackedRecords: page.Summary.TrackedUploads, MetadataDurable: page.Summary.MetadataDurable,
		QuarantineBytes: page.Summary.QuarantineBytes, OrphanedObjects: page.Summary.OrphanedObjects,
		OrphanedBytes: page.Summary.OrphanedBytes, RecentRecords: page.Resources,
	}
	cutoff := m.now().UTC().Add(-2 * m.inspectionTTL)
	m.mu.RLock()
	for _, entry := range m.uploads {
		if entry.Status != StatusQuarantined && entry.Status != StatusInspecting && entry.Status != StatusAccepted && entry.Status != StatusEncrypting {
			continue
		}
		created := entry.CreatedAt
		if posture.OldestPendingAt == nil || created.Before(*posture.OldestPendingAt) {
			value := created
			posture.OldestPendingAt = &value
		}
		if created.Before(cutoff) {
			posture.StuckProcessing++
		}
	}
	m.mu.RUnlock()
	return posture, nil
}

func NewManager(config Config) (*Manager, error) {
	if config.QuarantineDir == "" || config.MaxUploadBytes <= 0 || config.Scanner == nil {
		return nil, errors.New("invalid ingest configuration")
	}
	if config.InspectionTTL <= 0 {
		config.InspectionTTL = 5 * time.Second
	}
	if config.DefaultOwnerQuotaBytes <= 0 {
		config.DefaultOwnerQuotaBytes = 1024 * 1024 * 1024
	}
	if config.StorageCapacityBytes <= 0 {
		config.StorageCapacityBytes = 50 * 1024 * 1024 * 1024
	}
	if config.StorageReserveBytes < 0 || config.StorageReserveBytes >= config.StorageCapacityBytes {
		return nil, errors.New("invalid storage capacity reserve")
	}
	if config.StorageReserveBytes == 0 {
		config.StorageReserveBytes = config.StorageCapacityBytes / 10
	}
	if config.ReservationTTL <= 0 {
		config.ReservationTTL = time.Hour
	}
	if err := os.MkdirAll(config.QuarantineDir, 0o700); err != nil {
		return nil, err
	}
	if config.Repository == nil {
		config.Repository = NewMemoryRepository()
	}
	manager := &Manager{
		uploads:                make(map[string]*record),
		idempotency:            make(map[string]string),
		quarantineDir:          config.QuarantineDir,
		maxUploadBytes:         config.MaxUploadBytes,
		inspectionTTL:          config.InspectionTTL,
		transitionDelay:        config.TransitionDelay,
		scanner:                config.Scanner,
		repository:             config.Repository,
		defaultOwnerQuotaBytes: config.DefaultOwnerQuotaBytes,
		storageCapacityBytes:   config.StorageCapacityBytes, storageReserveBytes: config.StorageReserveBytes,
		reservationTTL:        config.ReservationTTL,
		ownerReservations:     make(map[string]int64),
		ownerQuotas:           make(map[string]int64),
		now:                   time.Now,
		protectedStore:        config.ProtectedStore,
		prepareLifecycleAudit: config.PrepareLifecycleAudit,
		deliverLifecycleAudit: config.DeliverLifecycleAudit,
	}
	persisted, err := config.Repository.LoadAll()
	if err != nil {
		return nil, err
	}
	quotas, err := config.Repository.LoadQuotas()
	if err != nil {
		return nil, err
	}
	manager.ownerQuotas = quotas
	resume := make([]string, 0)
	for _, stored := range persisted {
		entry, err := manager.recordFromPersisted(stored)
		if err != nil {
			return nil, err
		}
		manager.uploads[entry.ID] = entry
		manager.idempotency[entry.OwnerID+"\x00"+entry.IdempotencyHash] = entry.ID
		// The initial row is created before request streaming so PostgreSQL can
		// reference its capacity reservation. A zero-length quarantined row can
		// only mean the process stopped before reception committed; never inspect
		// a partial object left by that crash window.
		if entry.Status == StatusQuarantined && entry.Size == 0 {
			entry.Status, entry.Progress, entry.DecisionReason = StatusFailed, 100, "upload_reception_incomplete"
			event := LifecycleEvent{OwnerID: entry.OwnerID, UploadID: entry.ID, Action: "UPLOAD_RECOVERY_FAILED", Outcome: "failed", ReasonCode: entry.DecisionReason, CorrelationID: entry.CorrelationID, FromState: StatusQuarantined, ToState: StatusFailed}
			if err := manager.persistLifecycle(entry.persisted(), event); err != nil {
				return nil, err
			}
			_ = os.Remove(entry.QuarantinePath)
			_ = manager.repository.ReleaseCapacity(entry.ID)
			continue
		}
		if entry.Status == StatusQuarantined || entry.Status == StatusInspecting || entry.Status == StatusAccepted || entry.Status == StatusEncrypting {
			if _, err := os.Stat(entry.QuarantinePath); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return nil, err
				}
				from := entry.Status
				entry.Status = StatusFailed
				entry.Progress = 100
				entry.DecisionReason = "quarantine_object_missing"
				event := LifecycleEvent{OwnerID: entry.OwnerID, UploadID: entry.ID, Action: "UPLOAD_RECOVERY_FAILED", Outcome: "failed", ReasonCode: "quarantine_object_missing", CorrelationID: entry.CorrelationID, FromState: from, ToState: StatusFailed}
				if err := manager.persistLifecycle(entry.persisted(), event); err != nil {
					return nil, err
				}
			} else if entry.Status == StatusQuarantined || entry.Status == StatusInspecting || ((entry.Status == StatusAccepted || entry.Status == StatusEncrypting) && manager.protectedStore != nil) {
				resume = append(resume, entry.ID)
			}
		}
	}
	for _, uploadID := range resume {
		entry := manager.uploads[uploadID]
		if entry.Status == StatusQuarantined || entry.Status == StatusInspecting {
			go manager.inspect(uploadID)
		} else {
			go manager.protect(uploadID)
		}
	}
	return manager, nil
}

func (m *Manager) Create(ctx context.Context, ownerID, idempotencyKey, originalName, declaredMediaType string, source io.Reader) (Upload, bool, error) {
	return m.create(ctx, ownerID, idempotencyKey, originalName, declaredMediaType, source, 0)
}

// CreateSized is the network admission path. The declared size is treated as
// an upper bound and exact contract, not trusted metadata: streaming aborts if
// the body exceeds it and completion rejects a shorter body.
func (m *Manager) CreateSized(ctx context.Context, ownerID, idempotencyKey, originalName, declaredMediaType string, source io.Reader, expectedSize int64) (Upload, bool, error) {
	if expectedSize > m.maxUploadBytes {
		return Upload{}, false, ErrTooLarge
	}
	if expectedSize <= 0 {
		return Upload{}, false, ErrInvalidFile
	}
	return m.create(ctx, ownerID, idempotencyKey, originalName, declaredMediaType, source, expectedSize)
}

func (m *Manager) create(ctx context.Context, ownerID, idempotencyKey, originalName, declaredMediaType string, source io.Reader, expectedSize int64) (Upload, bool, error) {
	if len(idempotencyKey) < 8 || len(idempotencyKey) > 128 || strings.ContainsAny(idempotencyKey, "\r\n\x00") {
		return Upload{}, false, ErrInvalidKey
	}
	name := safeDisplayName(originalName)
	if name == "" || source == nil {
		return Upload{}, false, ErrInvalidFile
	}
	if declaredMediaType == "" {
		declaredMediaType = "application/octet-stream"
	}
	if len(declaredMediaType) > 255 || strings.ContainsAny(declaredMediaType, "\r\n\x00") {
		return Upload{}, false, ErrInvalidFile
	}

	idempotencyDigest := sha256.Sum256([]byte(idempotencyKey))
	idempotencyHash := hex.EncodeToString(idempotencyDigest[:])
	idempotencyIndex := ownerID + "\x00" + idempotencyHash
	m.mu.Lock()
	if existingID, exists := m.idempotency[idempotencyIndex]; exists {
		existing := *m.uploads[existingID]
		m.mu.Unlock()
		return existing.Upload, true, nil
	}

	uploadID, err := randomID("upl")
	if err != nil {
		m.mu.Unlock()
		return Upload{}, false, err
	}
	correlationID, err := randomID("corr")
	if err != nil {
		m.mu.Unlock()
		return Upload{}, false, err
	}
	quarantineObject := uploadID + ".upload"
	quarantinePath := filepath.Join(m.quarantineDir, quarantineObject)
	entry := &record{
		Upload: Upload{
			ID: uploadID, Name: name, DeclaredMediaType: declaredMediaType,
			DetectedMediaType: "application/octet-stream", Status: StatusQuarantined,
			Progress: 5, CorrelationID: correlationID, CreatedAt: m.now().UTC(),
		},
		OwnerID: ownerID, QuarantinePath: quarantinePath, QuarantineObject: quarantineObject,
		IdempotencyHash: idempotencyHash,
	}
	stored, reused, err := m.repository.Create(entry.persisted())
	if err != nil {
		m.mu.Unlock()
		return Upload{}, false, err
	}
	if reused {
		existing, err := m.recordFromPersisted(stored)
		if err != nil {
			m.mu.Unlock()
			return Upload{}, false, err
		}
		m.uploads[existing.ID] = existing
		m.idempotency[idempotencyIndex] = existing.ID
		m.mu.Unlock()
		return existing.Upload, true, nil
	}
	if expectedSize > 0 {
		now := m.now().UTC().Truncate(time.Microsecond)
		reservation := CapacityReservationRequest{
			UploadID: uploadID, OwnerID: ownerID, Bytes: expectedSize,
			OwnerQuotaBytes: m.ownerQuotaLocked(ownerID), StorageCapacityBytes: m.storageCapacityBytes,
			StorageReserveBytes: m.storageReserveBytes, Now: now, ExpiresAt: now.Add(m.reservationTTL),
		}
		if err := m.repository.ReserveCapacity(reservation); err != nil {
			_ = m.repository.Delete(uploadID)
			m.mu.Unlock()
			return Upload{}, false, err
		}
	}
	m.uploads[uploadID] = entry
	m.idempotency[idempotencyIndex] = uploadID
	m.mu.Unlock()

	var reservedBytes int64
	cleanup := func() {
		_ = os.Remove(quarantinePath)
		_ = m.repository.ReleaseCapacity(uploadID)
		_ = m.repository.Delete(uploadID)
		m.mu.Lock()
		if reservedBytes > 0 {
			m.ownerReservations[ownerID] -= reservedBytes
			if m.ownerReservations[ownerID] <= 0 {
				delete(m.ownerReservations, ownerID)
			}
			reservedBytes = 0
		}
		delete(m.uploads, uploadID)
		delete(m.idempotency, idempotencyIndex)
		m.mu.Unlock()
	}

	file, err := os.OpenFile(quarantinePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		return Upload{}, false, err
	}

	hasher := sha256.New()
	header := make([]byte, 0, 512)
	buffer := make([]byte, 32*1024)
	limited := &io.LimitedReader{R: source, N: m.maxUploadBytes + 1}
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			cleanup()
			return Upload{}, false, err
		}
		readCount, readErr := limited.Read(buffer)
		if readCount > 0 {
			chunkBytes := int64(readCount)
			if expectedSize > 0 {
				if size+chunkBytes > expectedSize {
					_ = file.Close()
					cleanup()
					return Upload{}, false, ErrInvalidFile
				}
			} else {
				m.mu.Lock()
				usedBytes := m.ownerQuotaUsageLocked(ownerID)
				if usedBytes+m.ownerReservations[ownerID]+chunkBytes > m.ownerQuotaLocked(ownerID) {
					m.mu.Unlock()
					_ = file.Close()
					cleanup()
					return Upload{}, false, ErrQuotaExceeded
				}
				m.ownerReservations[ownerID] += chunkBytes
				reservedBytes += chunkBytes
				m.mu.Unlock()
			}
			size += int64(readCount)
			if size > m.maxUploadBytes {
				_ = file.Close()
				cleanup()
				return Upload{}, false, ErrTooLarge
			}
			if len(header) < 512 {
				remaining := 512 - len(header)
				if remaining > readCount {
					remaining = readCount
				}
				header = append(header, buffer[:remaining]...)
			}
			if _, err := file.Write(buffer[:readCount]); err != nil {
				_ = file.Close()
				cleanup()
				return Upload{}, false, err
			}
			_, _ = hasher.Write(buffer[:readCount])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = file.Close()
			cleanup()
			return Upload{}, false, readErr
		}
	}
	if size == 0 {
		_ = file.Close()
		cleanup()
		return Upload{}, false, ErrInvalidFile
	}
	if expectedSize > 0 && size != expectedSize {
		_ = file.Close()
		cleanup()
		return Upload{}, false, ErrInvalidFile
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return Upload{}, false, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return Upload{}, false, err
	}

	m.mu.Lock()
	entry.Size = size
	m.ownerReservations[ownerID] -= reservedBytes
	if m.ownerReservations[ownerID] <= 0 {
		delete(m.ownerReservations, ownerID)
	}
	reservedBytes = 0
	entry.DetectedMediaType = http.DetectContentType(header)
	entry.Digest = hex.EncodeToString(hasher.Sum(nil))
	entry.Progress = 25
	response := entry.Upload
	m.mu.Unlock()
	quarantineEvent := LifecycleEvent{OwnerID: entry.OwnerID, UploadID: entry.ID, Action: "UPLOAD_QUARANTINED", Outcome: "success", ReasonCode: "quarantine_created", CorrelationID: entry.CorrelationID, ToState: StatusQuarantined}
	if err := m.persistLifecycle(entry.persisted(), quarantineEvent); err != nil {
		cleanup()
		return Upload{}, false, err
	}

	go m.inspect(uploadID)
	return response, false, nil
}

func (m *Manager) ownerQuotaUsageLocked(ownerID string) int64 {
	var used int64
	for _, entry := range m.uploads {
		if entry.OwnerID == ownerID && countsTowardQuota(entry.Status) {
			used += entry.Size
		}
	}
	return used
}

func (m *Manager) ownerQuotaLocked(ownerID string) int64 {
	if quota, exists := m.ownerQuotas[ownerID]; exists {
		return quota
	}
	return m.defaultOwnerQuotaBytes
}

func (m *Manager) SetOwnerQuota(ownerID string, quotaBytes int64) error {
	_, err := m.SetOwnerQuotaAudited(ownerID, quotaBytes, auditoutbox.Intent{})
	return err
}

func (m *Manager) SetOwnerQuotaAudited(ownerID string, quotaBytes int64, intent auditoutbox.Intent) (bool, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" || quotaBytes < 1024*1024 || quotaBytes > 10*1024*1024*1024*1024 {
		return false, ErrInvalidQuery
	}
	durable := false
	var err error
	if repository, ok := m.repository.(auditedQuotaRepository); ok && intent.EventID != "" {
		durable, err = true, repository.SetQuotaAudited(ownerID, quotaBytes, intent)
	} else {
		err = m.repository.SetQuota(ownerID, quotaBytes)
	}
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	m.ownerQuotas[ownerID] = quotaBytes
	m.mu.Unlock()
	return durable, nil
}

// ResetOwnerQuotaAudited removes the account-specific override so future
// capacity reservations use the organization default. It deliberately does
// not copy the current default into an override because defaults may change.
func (m *Manager) ResetOwnerQuotaAudited(ownerID string, intent auditoutbox.Intent) (bool, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return false, ErrInvalidQuery
	}
	durable := false
	var err error
	if repository, ok := m.repository.(auditedQuotaRepository); ok && intent.EventID != "" {
		durable, err = true, repository.DeleteQuotaAudited(ownerID, intent)
	} else {
		err = m.repository.DeleteQuota(ownerID)
	}
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	delete(m.ownerQuotas, ownerID)
	m.mu.Unlock()
	return durable, nil
}

func (m *Manager) Get(ownerID, uploadID string) (Upload, error) {
	m.mu.RLock()
	entry, exists := m.uploads[uploadID]
	if !exists || entry.OwnerID != ownerID {
		m.mu.RUnlock()
		return Upload{}, ErrNotFound
	}
	response := entry.Upload
	m.mu.RUnlock()
	return response, nil
}

// ListOwnerUploads returns only the authenticated owner's safe file metadata.
// Storage locators, digests, envelope fields, and key material never cross the
// user API boundary.
func (m *Manager) ListOwnerUploads(ownerID string) []Upload {
	m.mu.RLock()
	files := make([]Upload, 0)
	for _, entry := range m.uploads {
		if entry.OwnerID == ownerID {
			files = append(files, entry.Upload)
		}
	}
	m.mu.RUnlock()
	sort.Slice(files, func(i, j int) bool {
		if files[i].CreatedAt.Equal(files[j].CreatedAt) {
			return files[i].ID < files[j].ID
		}
		return files[i].CreatedAt.After(files[j].CreatedAt)
	})
	return files
}

// ListAdminResources returns safe metadata for operational governance. The
// current manager is process-local, which is surfaced explicitly in Summary;
// callers must not present these figures as durable storage accounting.
func (m *Manager) ListAdminResources(search string, limit, offset int) (AdminResourcePage, error) {
	search = strings.ToLower(strings.TrimSpace(search))
	if len(search) > 120 {
		return AdminResourcePage{}, ErrInvalidQuery
	}
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	m.mu.RLock()
	resources := make([]AdminResource, 0, len(m.uploads))
	knownObjects := make(map[string]struct{}, len(m.uploads))
	usageByOwner := make(map[string]OwnerUsage)
	durable := m.repository.Durable()
	now := m.now().UTC()
	summary := AdminResourceSummary{
		TrackedUploads: len(m.uploads), StatusCounts: make(map[Status]int),
		MetadataDurable: durable, RuntimeOnly: !durable, ProtectedConnected: m.protectedStore != nil,
		OwnerUsage: make([]OwnerUsage, 0), DefaultQuotaBytes: m.defaultOwnerQuotaBytes,
		QuotaOverrides:       make([]QuotaOverride, 0),
		StorageCapacityBytes: m.storageCapacityBytes, StorageReserveBytes: m.storageReserveBytes,
	}
	for ownerID, quota := range m.ownerQuotas {
		summary.QuotaOverrides = append(summary.QuotaOverrides, QuotaOverride{OwnerID: ownerID, QuotaBytes: quota})
	}
	for _, entry := range m.uploads {
		knownObjects[entry.QuarantineObject] = struct{}{}
		summary.TrackedBytes += entry.Size
		summary.StatusCounts[entry.Status]++
		if countsTowardQuota(entry.Status) {
			usage := usageByOwner[entry.OwnerID]
			usage.OwnerID = entry.OwnerID
			usage.QuotaBytes = m.ownerQuotaLocked(entry.OwnerID)
			usage.Uploads++
			usage.Bytes += entry.Size
			usageByOwner[entry.OwnerID] = usage
		}
		if entry.Status == StatusQuarantined || entry.Status == StatusInspecting || entry.Status == StatusAccepted || entry.Status == StatusEncrypting {
			summary.PendingProcessing++
		}
		age := now.Sub(entry.CreatedAt)
		if age >= 0 && age <= 24*time.Hour {
			summary.BytesLast24Hours += entry.Size
		}
		if age >= 0 && age <= 7*24*time.Hour {
			summary.BytesLast7Days += entry.Size
		}
		if search != "" && !strings.Contains(strings.ToLower(entry.Name), search) &&
			!strings.Contains(strings.ToLower(entry.OwnerID), search) &&
			!strings.Contains(strings.ToLower(string(entry.Status)), search) {
			continue
		}
		resources = append(resources, AdminResource{
			ID: entry.ID, OwnerID: entry.OwnerID, Name: entry.Name, Size: entry.Size,
			DeclaredMediaType: entry.DeclaredMediaType, DetectedMediaType: entry.DetectedMediaType,
			Status: entry.Status, DecisionReason: entry.DecisionReason,
			CorrelationID: entry.CorrelationID, CreatedAt: entry.CreatedAt,
		})
	}
	m.mu.RUnlock()
	sort.Slice(summary.QuotaOverrides, func(i, j int) bool { return summary.QuotaOverrides[i].OwnerID < summary.QuotaOverrides[j].OwnerID })
	for _, usage := range usageByOwner {
		summary.OwnerUsage = append(summary.OwnerUsage, usage)
		if usage.Bytes >= usage.QuotaBytes-usage.QuotaBytes/5 {
			summary.QuotaAlerts++
		}
	}
	sort.Slice(summary.OwnerUsage, func(i, j int) bool {
		if summary.OwnerUsage[i].Bytes == summary.OwnerUsage[j].Bytes {
			return summary.OwnerUsage[i].OwnerID < summary.OwnerUsage[j].OwnerID
		}
		return summary.OwnerUsage[i].Bytes > summary.OwnerUsage[j].Bytes
	})
	if len(summary.OwnerUsage) > 10 {
		summary.OwnerUsage = summary.OwnerUsage[:10]
	}
	reservations, err := m.repository.CapacityReservationSummary(now)
	if err != nil {
		return AdminResourcePage{}, err
	}
	summary.ActiveReservations, summary.ReservedCapacityBytes = reservations.Active, reservations.Bytes

	// Disk usage is measured from the quarantine directory itself rather than
	// inferred from lifecycle state, so rejected/failed cleanup is reflected.
	entries, err := os.ReadDir(m.quarantineDir)
	if err != nil {
		return AdminResourcePage{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return AdminResourcePage{}, err
		}
		summary.QuarantineBytes += info.Size()
		if _, tracked := knownObjects[entry.Name()]; !tracked {
			summary.OrphanedObjects++
			summary.OrphanedBytes += info.Size()
		}
	}

	sort.Slice(resources, func(i, j int) bool {
		if resources[i].CreatedAt.Equal(resources[j].CreatedAt) {
			return resources[i].ID < resources[j].ID
		}
		return resources[i].CreatedAt.After(resources[j].CreatedAt)
	})
	total := len(resources)
	if offset >= total {
		return AdminResourcePage{Resources: []AdminResource{}, Summary: summary, Total: total, Limit: limit, Offset: offset}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return AdminResourcePage{Resources: resources[offset:end], Summary: summary, Total: total, Limit: limit, Offset: offset}, nil
}

func (m *Manager) inspect(uploadID string) {
	if m.transitionDelay > 0 {
		time.Sleep(m.transitionDelay)
	}
	m.mu.Lock()
	entry, exists := m.uploads[uploadID]
	if !exists {
		m.mu.Unlock()
		return
	}
	entry.Status = StatusInspecting
	entry.Progress = 60
	evidence := Evidence{Name: entry.Name, Digest: entry.Digest, DetectedMediaType: entry.DetectedMediaType, QuarantinePath: entry.QuarantinePath}
	transition := entry.persisted()
	m.mu.Unlock()
	inspectionStarted := LifecycleEvent{OwnerID: entry.OwnerID, UploadID: entry.ID, Action: "FILE_INSPECTION_STARTED", Outcome: "success", ReasonCode: "content_policy_evaluation", CorrelationID: entry.CorrelationID, FromState: StatusQuarantined, ToState: StatusInspecting}
	if err := m.persistLifecycle(transition, inspectionStarted); err != nil {
		m.failPersistence(uploadID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.inspectionTTL)
	result, err := m.scanner.Inspect(ctx, evidence)
	cancel()

	m.mu.Lock()
	entry, exists = m.uploads[uploadID]
	if !exists {
		m.mu.Unlock()
		return
	}
	// Build the completed state without publishing it to readers. PostgreSQL
	// and its audit outbox must commit before Get can report a terminal result.
	terminal := entry.persisted()
	terminal.Progress = 100
	switch {
	case err != nil:
		terminal.Status = StatusFailed
		terminal.DecisionReason = "inspection_unavailable"
	case !result.Accepted:
		terminal.Status = StatusRejected
		terminal.DecisionReason = result.Reason
	default:
		terminal.Status = StatusAccepted
		terminal.DecisionReason = "policy_accepted"
		if m.protectedStore != nil {
			terminal.Progress = 75
		}
	}
	path := entry.QuarantinePath
	removePlaintext := terminal.Status == StatusRejected || terminal.Status == StatusFailed
	m.mu.Unlock()
	inspectionOutcome := "success"
	if terminal.Status == StatusRejected {
		inspectionOutcome = "denied"
	}
	if terminal.Status == StatusFailed {
		inspectionOutcome = "failed"
	}
	inspectionCompleted := LifecycleEvent{OwnerID: terminal.OwnerID, UploadID: terminal.ID, Action: "FILE_INSPECTION_COMPLETED", Outcome: inspectionOutcome, ReasonCode: terminal.DecisionReason, CorrelationID: terminal.CorrelationID, FromState: StatusInspecting, ToState: terminal.Status}
	if err := m.persistLifecycle(terminal, inspectionCompleted); err != nil {
		m.failPersistence(uploadID)
		return
	}
	m.mu.Lock()
	entry, exists = m.uploads[uploadID]
	if !exists {
		m.mu.Unlock()
		return
	}
	entry.Upload = terminal.Upload
	m.mu.Unlock()
	if removePlaintext {
		_ = os.Remove(path)
		_ = m.repository.ReleaseCapacity(uploadID)
	} else if terminal.Status == StatusAccepted && m.protectedStore != nil {
		m.protect(uploadID)
	} else if terminal.Status == StatusAccepted {
		_ = m.repository.ReleaseCapacity(uploadID)
	}
}

// protect converts policy-accepted quarantine plaintext into one immutable
// authenticated ciphertext version. The plaintext is removed only after both
// protected metadata and the stored lifecycle state are durable.
func (m *Manager) protect(uploadID string) {
	m.mu.Lock()
	entry, exists := m.uploads[uploadID]
	if !exists || (entry.Status != StatusAccepted && entry.Status != StatusEncrypting) {
		m.mu.Unlock()
		return
	}
	entry.Status = StatusEncrypting
	entry.Progress = 85
	entry.DecisionReason = "protection_in_progress"
	transition := entry.persisted()
	path := entry.QuarantinePath
	request := protectedstore.Request{
		UploadID: entry.ID, OwnerID: entry.OwnerID, PlaintextSize: entry.Size,
		PlaintextDigest: entry.Digest, MediaType: entry.DetectedMediaType,
		InspectionRecordID: entry.ID,
	}
	m.mu.Unlock()
	protectionStarted := LifecycleEvent{OwnerID: transition.OwnerID, UploadID: transition.ID, Action: "FILE_PROTECTION_STARTED", Outcome: "success", ReasonCode: "policy_accepted", CorrelationID: transition.CorrelationID, FromState: StatusAccepted, ToState: StatusEncrypting}
	if err := m.persistLifecycle(transition, protectionStarted); err != nil {
		m.failPersistence(uploadID)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		m.failProtection(uploadID, "quarantine_object_missing")
		return
	}
	metadata, protectionErr := m.protectedStore.Protect(context.Background(), request, file)
	closeErr := file.Close()
	if protectionErr != nil || closeErr != nil {
		m.failProtection(uploadID, "protection_unavailable")
		return
	}
	// A file is not reported as stored until its immutable version is also
	// present in the owner-scoped catalog. This keeps the user-facing inventory
	// authoritative instead of deriving it from temporary ingestion state.
	if _, _, err := m.protectedStore.RegisterInitial(entry.OwnerID, entry.Name, metadata); err != nil {
		m.failProtection(uploadID, "version_catalog_unavailable")
		return
	}
	m.mu.Lock()
	entry, exists = m.uploads[uploadID]
	if !exists {
		m.mu.Unlock()
		return
	}
	entry.Status = StatusStored
	entry.Progress = 100
	entry.DecisionReason = "protected_storage_committed"
	stored := entry.persisted()
	lifecycleEvent := LifecycleEvent{OwnerID: entry.OwnerID, UploadID: entry.ID, Action: "FILE_PROTECTED", Outcome: "success", ReasonCode: "protected_storage_committed", CorrelationID: entry.CorrelationID, FromState: StatusEncrypting, ToState: StatusStored}
	m.mu.Unlock()
	if err := m.persistLifecycle(stored, lifecycleEvent); err != nil {
		m.failPersistence(uploadID)
		return
	}
	_ = os.Remove(path)
	_ = m.repository.ReleaseCapacity(uploadID)
}

func (m *Manager) failProtection(uploadID, reason string) {
	m.mu.Lock()
	entry, exists := m.uploads[uploadID]
	if !exists {
		m.mu.Unlock()
		return
	}
	entry.Status = StatusFailed
	entry.Progress = 100
	entry.DecisionReason = reason
	failed := entry.persisted()
	path := entry.QuarantinePath
	lifecycleEvent := LifecycleEvent{OwnerID: entry.OwnerID, UploadID: entry.ID, Action: "FILE_PROTECTION_FAILED", Outcome: "failed", ReasonCode: reason, CorrelationID: entry.CorrelationID, FromState: StatusEncrypting, ToState: StatusFailed}
	m.mu.Unlock()
	_ = m.persistLifecycle(failed, lifecycleEvent)
	_ = os.Remove(path)
	_ = m.repository.ReleaseCapacity(uploadID)
}

// persistLifecycle commits the authoritative transition and its sanitized
// audit intent together when PostgreSQL is configured. Memory-mode tests keep
// the same event semantics, but cannot claim transactional durability.
func (m *Manager) persistLifecycle(record persistedRecord, event LifecycleEvent) error {
	if m.prepareLifecycleAudit == nil {
		return m.repository.Update(record)
	}
	intent, err := m.prepareLifecycleAudit(event)
	if err != nil {
		return err
	}
	durable := false
	if repository, ok := m.repository.(auditedTransitionRepository); ok {
		durable = true
		err = repository.UpdateAudited(record, intent)
	} else {
		err = m.repository.Update(record)
	}
	if err != nil {
		return err
	}
	if m.deliverLifecycleAudit != nil {
		m.deliverLifecycleAudit(intent, durable)
	}
	return nil
}

func (m *Manager) failPersistence(uploadID string) {
	m.mu.Lock()
	entry, exists := m.uploads[uploadID]
	if !exists {
		m.mu.Unlock()
		return
	}
	entry.Status = StatusFailed
	entry.Progress = 100
	entry.DecisionReason = "metadata_persistence_unavailable"
	failed := entry.persisted()
	path := entry.QuarantinePath
	m.mu.Unlock()
	// A retry is best effort; if the metadata store remains unavailable, the
	// quarantine object is still removed so a persistence failure cannot make
	// untrusted plaintext available as an accepted resource.
	_ = m.repository.Update(failed)
	_ = os.Remove(path)
	_ = m.repository.ReleaseCapacity(uploadID)
}

func (entry *record) persisted() persistedRecord {
	return persistedRecord{
		Upload: entry.Upload, OwnerID: entry.OwnerID,
		QuarantineObject: entry.QuarantineObject, Digest: entry.Digest,
		IdempotencyHash: entry.IdempotencyHash,
	}
}

func (m *Manager) recordFromPersisted(stored persistedRecord) (*record, error) {
	if stored.ID == "" || stored.OwnerID == "" || stored.QuarantineObject != stored.ID+".upload" ||
		len(stored.IdempotencyHash) != sha256.Size*2 || !validStatus(stored.Status) {
		return nil, errors.New("invalid persisted upload metadata")
	}
	return &record{
		Upload: stored.Upload, OwnerID: stored.OwnerID,
		QuarantineObject: stored.QuarantineObject,
		QuarantinePath:   filepath.Join(m.quarantineDir, stored.QuarantineObject),
		Digest:           stored.Digest, IdempotencyHash: stored.IdempotencyHash,
	}, nil
}

func validStatus(status Status) bool {
	switch status {
	case StatusQuarantined, StatusInspecting, StatusAccepted, StatusEncrypting, StatusStored, StatusRejected, StatusFailed:
		return true
	default:
		return false
	}
}

func countsTowardQuota(status Status) bool {
	return status == StatusQuarantined || status == StatusInspecting || status == StatusAccepted || status == StatusEncrypting || status == StatusStored
}

func safeDisplayName(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	value = filepath.Base(value)
	value = strings.TrimSpace(value)
	if value == "." || len(value) == 0 || len(value) > 255 || strings.ContainsAny(value, "\r\n\x00") {
		return ""
	}
	return value
}

func randomID(prefix string) (string, error) {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}
