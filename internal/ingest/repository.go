package ingest

import (
	"errors"
	"sync"
	"time"

	"securestore/internal/auditoutbox"
)

type CapacityReservationRequest struct {
	UploadID, OwnerID                         string
	Bytes, OwnerQuotaBytes                    int64
	StorageCapacityBytes, StorageReserveBytes int64
	Now, ExpiresAt                            time.Time
}

type CapacityReservationSummary struct {
	Active int   `json:"active"`
	Bytes  int64 `json:"bytes"`
}

type persistedRecord struct {
	Upload
	OwnerID          string
	QuarantineObject string
	Digest           string
	IdempotencyHash  string
}

// Repository stores lifecycle metadata only. Quarantine bytes remain in the
// isolated filesystem and protected versions will use a separate store.
type Repository interface {
	LoadAll() ([]persistedRecord, error)
	Create(persistedRecord) (persistedRecord, bool, error)
	Update(persistedRecord) error
	Delete(uploadID string) error
	Durable() bool
	LoadQuotas() (map[string]int64, error)
	SetQuota(ownerID string, quotaBytes int64) error
	DeleteQuota(ownerID string) error
	ReserveCapacity(CapacityReservationRequest) error
	ReleaseCapacity(uploadID string) error
	CapacityReservationSummary(time.Time) (CapacityReservationSummary, error)
}

type auditedQuotaRepository interface {
	SetQuotaAudited(string, int64, auditoutbox.Intent) error
	DeleteQuotaAudited(string, auditoutbox.Intent) error
}

type auditedTransitionRepository interface {
	UpdateAudited(persistedRecord, auditoutbox.Intent) error
}

type MemoryRepository struct {
	mu            sync.RWMutex
	records       map[string]persistedRecord
	byIdempotency map[string]string
	quotas        map[string]int64
	reservations  map[string]CapacityReservationRequest
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{records: make(map[string]persistedRecord), byIdempotency: make(map[string]string), quotas: make(map[string]int64), reservations: make(map[string]CapacityReservationRequest)}
}

func (r *MemoryRepository) LoadAll() ([]persistedRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	records := make([]persistedRecord, 0, len(r.records))
	for _, record := range r.records {
		records = append(records, record)
	}
	return records, nil
}

func (r *MemoryRepository) Create(record persistedRecord) (persistedRecord, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := record.OwnerID + "\x00" + record.IdempotencyHash
	if existingID, exists := r.byIdempotency[index]; exists {
		return r.records[existingID], true, nil
	}
	r.records[record.ID] = record
	r.byIdempotency[index] = record.ID
	return record, false, nil
}

func (r *MemoryRepository) Update(record persistedRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.records[record.ID]; !exists {
		return ErrNotFound
	}
	r.records[record.ID] = record
	return nil
}

func (r *MemoryRepository) Delete(uploadID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.records[uploadID]
	if !exists {
		return nil
	}
	delete(r.byIdempotency, record.OwnerID+"\x00"+record.IdempotencyHash)
	delete(r.records, uploadID)
	delete(r.reservations, uploadID)
	return nil
}

func (r *MemoryRepository) ReserveCapacity(request CapacityReservationRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if request.Bytes <= 0 || request.OwnerQuotaBytes <= 0 || request.StorageCapacityBytes <= request.StorageReserveBytes || !request.ExpiresAt.After(request.Now) {
		return ErrInvalidQuery
	}
	for uploadID, reservation := range r.reservations {
		if !reservation.ExpiresAt.After(request.Now) {
			delete(r.reservations, uploadID)
		}
	}
	if existing, ok := r.reservations[request.UploadID]; ok {
		if existing.OwnerID == request.OwnerID && existing.Bytes == request.Bytes {
			return nil
		}
		return errors.New("capacity reservation conflict")
	}
	var ownerUsage, ownerReserved, globalUsage, globalReserved int64
	for uploadID, record := range r.records {
		if !countsTowardQuota(record.Status) {
			continue
		}
		if _, reserved := r.reservations[uploadID]; reserved {
			continue
		}
		globalUsage += record.Size
		if record.OwnerID == request.OwnerID {
			ownerUsage += record.Size
		}
	}
	for _, reservation := range r.reservations {
		globalReserved += reservation.Bytes
		if reservation.OwnerID == request.OwnerID {
			ownerReserved += reservation.Bytes
		}
	}
	if ownerUsage+ownerReserved+request.Bytes > request.OwnerQuotaBytes {
		return ErrQuotaExceeded
	}
	if globalUsage+globalReserved+request.Bytes > request.StorageCapacityBytes-request.StorageReserveBytes {
		return ErrCapacityExceeded
	}
	r.reservations[request.UploadID] = request
	return nil
}

func (r *MemoryRepository) ReleaseCapacity(uploadID string) error {
	r.mu.Lock()
	delete(r.reservations, uploadID)
	r.mu.Unlock()
	return nil
}

func (r *MemoryRepository) CapacityReservationSummary(now time.Time) (CapacityReservationSummary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	summary := CapacityReservationSummary{}
	for uploadID, reservation := range r.reservations {
		if !reservation.ExpiresAt.After(now) {
			delete(r.reservations, uploadID)
			continue
		}
		summary.Active++
		summary.Bytes += reservation.Bytes
	}
	return summary, nil
}

func (*MemoryRepository) Durable() bool { return false }

func (r *MemoryRepository) LoadQuotas() (map[string]int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	quotas := make(map[string]int64, len(r.quotas))
	for ownerID, quota := range r.quotas {
		quotas[ownerID] = quota
	}
	return quotas, nil
}

func (r *MemoryRepository) SetQuota(ownerID string, quotaBytes int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.quotas[ownerID] = quotaBytes
	return nil
}

func (r *MemoryRepository) DeleteQuota(ownerID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.quotas, ownerID)
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
