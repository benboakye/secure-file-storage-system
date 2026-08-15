package protectedstore

import (
	"errors"
	"sort"
	"sync"
	"time"

	"securestore/internal/auditoutbox"
)

type MemoryRepository struct {
	mu              sync.RWMutex
	entries         map[string]Metadata
	files           map[string]LogicalFile
	versions        map[string][]Version
	grants          map[string]Grant
	lifecycle       map[string]LifecycleFile
	purges          map[string]PurgeResult
	deletions       map[string]DeletionOperation
	drills          []RecoveryDrill
	reconciliations map[string]OrphanReconciliationOperation
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{entries: make(map[string]Metadata), files: make(map[string]LogicalFile), versions: make(map[string][]Version), grants: make(map[string]Grant), lifecycle: make(map[string]LifecycleFile), purges: make(map[string]PurgeResult), deletions: make(map[string]DeletionOperation), reconciliations: make(map[string]OrphanReconciliationOperation)}
}

func (r *MemoryRepository) AuthorizeOrphanReconciliation(operation OrphanReconciliationOperation, _ auditoutbox.Intent) (OrphanReconciliationOperation, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.reconciliations {
		if existing.Token == operation.Token {
			return existing, false, nil
		}
	}
	r.reconciliations[operation.OperationID] = operation
	return operation, true, nil
}

func (r *MemoryRepository) CompleteOrphanReconciliation(operationID, status, reasonCode string, completedAt time.Time, _ auditoutbox.Intent) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	operation, ok := r.reconciliations[operationID]
	if !ok || operation.Status != ReconciliationAuthorized {
		return false, nil
	}
	operation.Status, operation.ReasonCode = status, reasonCode
	operation.CompletedAt = &completedAt
	r.reconciliations[operationID] = operation
	return true, nil
}

func (r *MemoryRepository) PendingOrphanReconciliations(limit int) ([]OrphanReconciliationOperation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]OrphanReconciliationOperation, 0, limit)
	for _, operation := range r.reconciliations {
		if operation.Status == ReconciliationAuthorized {
			result = append(result, operation)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].AuthorizedAt.Equal(result[j].AuthorizedAt) {
			return result[i].OperationID < result[j].OperationID
		}
		return result[i].AuthorizedAt.Before(result[j].AuthorizedAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

var _ orphanReconciliationRepository = (*MemoryRepository)(nil)

func (r *MemoryRepository) Create(metadata Metadata) (Metadata, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.entries[metadata.UploadID]; ok {
		return cloneMetadata(existing), true, nil
	}
	r.entries[metadata.UploadID] = cloneMetadata(metadata)
	return cloneMetadata(metadata), false, nil
}

func (r *MemoryRepository) FindByUpload(ownerID, uploadID string) (Metadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	metadata, ok := r.entries[uploadID]
	if !ok || metadata.OwnerID != ownerID {
		return Metadata{}, ErrNotFound
	}
	return cloneMetadata(metadata), nil
}

func (*MemoryRepository) Durable() bool { return false }

func (r *MemoryRepository) ProtectedBlobObjectExists(object string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, metadata := range r.entries {
		if metadata.BlobObject == object && len(metadata.WrappedDEK) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (r *MemoryRepository) KeyRotationPosture(currentID, currentVersion string) (KeyRotationPosture, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := KeyRotationPosture{CurrentKEKID: currentID, CurrentKEKVersion: currentVersion, ProtectedVersions: len(r.entries), Durable: false}
	for _, metadata := range r.entries {
		id, version := wrappingKeyIdentity(metadata)
		if id == currentID && version == currentVersion {
			result.CurrentVersions++
		} else {
			result.PendingVersions++
		}
	}
	return result, nil
}

func (r *MemoryRepository) ListDEKRewrapCandidates(currentID, currentVersion string, limit int) ([]Metadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Metadata, 0, limit)
	for _, metadata := range r.entries {
		id, version := wrappingKeyIdentity(metadata)
		if len(metadata.WrappedDEK) > 0 && (id != currentID || version != currentVersion) {
			result = append(result, cloneMetadata(metadata))
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func (r *MemoryRepository) CommitDEKRewrap(candidate Metadata, replacement []byte, targetID, targetVersion, _ string, _ time.Time, _ auditoutbox.Intent) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.entries[candidate.UploadID]
	if !ok || stored.VersionID != candidate.VersionID || !sameWrappedDEK(stored.WrappedDEK, candidate.WrappedDEK) {
		return false, nil
	}
	stored.WrappedDEK = append([]byte(nil), replacement...)
	stored.WrappingKEKID, stored.WrappingKEKVersion = targetID, targetVersion
	r.entries[candidate.UploadID] = stored
	return true, nil
}

var _ rewrapRepository = (*MemoryRepository)(nil)

func cloneMetadata(value Metadata) Metadata {
	value.Nonce = append([]byte(nil), value.Nonce...)
	value.WrappedDEK = append([]byte(nil), value.WrappedDEK...)
	return value
}

var _ Repository = (*MemoryRepository)(nil)

func (r *MemoryRepository) RegisterInitial(ownerID, name string, metadata Metadata) (LogicalFile, Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, file := range r.files {
		if file.OwnerID == ownerID && file.CurrentVersionID == metadata.VersionID {
			return file, r.versions[file.FileID][0], nil
		}
	}
	fileID, err := opaqueID("file")
	if err != nil {
		return LogicalFile{}, Version{}, err
	}
	file := LogicalFile{FileID: fileID, OwnerID: ownerID, Name: name, CurrentVersionID: metadata.VersionID, CreatedAt: metadata.CreatedAt, UpdatedAt: metadata.CreatedAt}
	version := Version{FileID: fileID, VersionID: metadata.VersionID, OperationID: metadata.UploadID, Number: 1, PlaintextSize: metadata.PlaintextSize, MediaType: metadata.MediaType, Reason: "initial_upload", Current: true, CreatedAt: metadata.CreatedAt}
	r.files[fileID], r.versions[fileID] = file, []Version{version}
	r.lifecycle[fileID] = LifecycleFile{LogicalFile: file}
	return file, version, nil
}

func (r *MemoryRepository) ListFiles(ownerID string) ([]LogicalFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := []LogicalFile{}
	for _, file := range r.files {
		state := r.lifecycle[file.FileID]
		if file.OwnerID == ownerID && state.DeletedAt == nil && state.PurgedAt == nil {
			result = append(result, file)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UpdatedAt.After(result[j].UpdatedAt) })
	return result, nil
}
func (r *MemoryRepository) Details(ownerID, fileID string) (Details, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	file, ok := r.files[fileID]
	state := r.lifecycle[fileID]
	if !ok || file.OwnerID != ownerID || state.DeletedAt != nil || state.PurgedAt != nil {
		return Details{}, ErrNotFound
	}
	return Details{File: file, Versions: append([]Version(nil), r.versions[fileID]...), Access: "owner"}, nil
}
func (r *MemoryRepository) FindVersion(ownerID, fileID, versionID string) (Metadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	file, ok := r.files[fileID]
	state := r.lifecycle[fileID]
	if !ok || file.OwnerID != ownerID || state.DeletedAt != nil || state.PurgedAt != nil {
		return Metadata{}, ErrNotFound
	}
	for _, version := range r.versions[fileID] {
		if version.VersionID == versionID {
			for _, metadata := range r.entries {
				if metadata.VersionID == versionID {
					return cloneMetadata(metadata), nil
				}
			}
		}
	}
	return Metadata{}, ErrNotFound
}
func (r *MemoryRepository) CommitRestore(ownerID, fileID, sourceVersionID string, metadata Metadata) (Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	file, ok := r.files[fileID]
	if !ok || file.OwnerID != ownerID {
		return Version{}, ErrNotFound
	}
	for _, existing := range r.versions[fileID] {
		if existing.OperationID == metadata.UploadID {
			if existing.SourceVersionID != sourceVersionID {
				return Version{}, errors.New("restore idempotency conflict")
			}
			return existing, nil
		}
	}
	sourceFound := false
	for _, existing := range r.versions[fileID] {
		if existing.VersionID == sourceVersionID {
			sourceFound = true
			break
		}
	}
	if !sourceFound {
		return Version{}, ErrNotFound
	}
	for index := range r.versions[fileID] {
		r.versions[fileID][index].Current = false
	}
	version := Version{FileID: fileID, VersionID: metadata.VersionID, SourceVersionID: sourceVersionID, OperationID: metadata.UploadID, Number: int64(len(r.versions[fileID]) + 1), PlaintextSize: metadata.PlaintextSize, MediaType: metadata.MediaType, Reason: "verified_restore", Current: true, CreatedAt: metadata.CreatedAt}
	r.versions[fileID] = append([]Version{version}, r.versions[fileID]...)
	file.CurrentVersionID, file.UpdatedAt = metadata.VersionID, metadata.CreatedAt
	r.files[fileID] = file
	return version, nil
}

var _ CatalogRepository = (*MemoryRepository)(nil)

func (r *MemoryRepository) CreateGrant(ownerID, fileID string, recipient Recipient, permission string, expiresAt *time.Time) (Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	file, ok := r.files[fileID]
	if !ok || file.OwnerID != ownerID || recipient.ID == ownerID {
		return Grant{}, ErrNotFound
	}
	for id, existing := range r.grants {
		if existing.FileID == fileID && existing.RecipientID == recipient.ID && existing.RevokedAt == nil {
			existing.Permission, existing.ExpiresAt, existing.CreatedAt = permission, cloneTimeValue(expiresAt), time.Now().UTC()
			r.grants[id] = existing
			return existing, nil
		}
	}
	id, err := opaqueID("grant")
	if err != nil {
		return Grant{}, err
	}
	grant := Grant{GrantID: id, FileID: fileID, OwnerID: ownerID, RecipientID: recipient.ID, RecipientName: recipient.Name, RecipientEmail: recipient.Email, Permission: permission, ExpiresAt: cloneTimeValue(expiresAt), CreatedAt: time.Now().UTC()}
	r.grants[id] = grant
	return grant, nil
}

func (r *MemoryRepository) ListGrants(ownerID, fileID string) ([]Grant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	file, ok := r.files[fileID]
	if !ok || file.OwnerID != ownerID {
		return nil, ErrNotFound
	}
	now, grants := time.Now().UTC(), []Grant{}
	for _, grant := range r.grants {
		if grant.FileID == fileID && grant.OwnerID == ownerID && grant.RevokedAt == nil && (grant.ExpiresAt == nil || grant.ExpiresAt.After(now)) {
			grants = append(grants, grant)
		}
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].CreatedAt.After(grants[j].CreatedAt) })
	return grants, nil
}

func (r *MemoryRepository) RevokeGrant(ownerID, fileID, grantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	grant, ok := r.grants[grantID]
	if !ok || grant.OwnerID != ownerID || grant.FileID != fileID || grant.RevokedAt != nil {
		return ErrNotFound
	}
	now := time.Now().UTC()
	grant.RevokedAt = &now
	r.grants[grantID] = grant
	return nil
}

func (r *MemoryRepository) authorized(requesterID, fileID, capability string) (LogicalFile, string, bool) {
	file, ok := r.files[fileID]
	state := r.lifecycle[fileID]
	if !ok || state.DeletedAt != nil || state.PurgedAt != nil {
		return LogicalFile{}, "", false
	}
	if file.OwnerID == requesterID {
		return file, "owner", true
	}
	now := time.Now().UTC()
	for _, grant := range r.grants {
		if grant.FileID == fileID && grant.RecipientID == requesterID && grant.RevokedAt == nil && (grant.ExpiresAt == nil || grant.ExpiresAt.After(now)) && (capability == PermissionRead || grant.Permission == PermissionDownload) {
			return file, grant.Permission, true
		}
	}
	return LogicalFile{}, "", false
}
func (r *MemoryRepository) AuthorizedDetails(requesterID, fileID, capability string) (Details, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	file, access, ok := r.authorized(requesterID, fileID, capability)
	if !ok {
		return Details{}, ErrNotFound
	}
	return Details{File: file, Versions: append([]Version(nil), r.versions[fileID]...), Access: access}, nil
}
func (r *MemoryRepository) AuthorizedCurrentMetadata(requesterID, fileID, capability string) (Metadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	file, _, ok := r.authorized(requesterID, fileID, capability)
	if !ok {
		return Metadata{}, ErrNotFound
	}
	for _, metadata := range r.entries {
		if metadata.VersionID == file.CurrentVersionID {
			return cloneMetadata(metadata), nil
		}
	}
	return Metadata{}, ErrNotFound
}
func (r *MemoryRepository) ListSharedFiles(recipientID string) ([]SharedFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now, files := time.Now().UTC(), []SharedFile{}
	for _, grant := range r.grants {
		state := r.lifecycle[grant.FileID]
		if state.DeletedAt == nil && state.PurgedAt == nil && grant.RecipientID == recipientID && grant.RevokedAt == nil && (grant.ExpiresAt == nil || grant.ExpiresAt.After(now)) {
			if file, ok := r.files[grant.FileID]; ok {
				files = append(files, SharedFile{LogicalFile: file, OwnerName: "File owner", Permission: grant.Permission})
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].UpdatedAt.After(files[j].UpdatedAt) })
	return files, nil
}
func cloneTimeValue(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

var _ AccessRepository = (*MemoryRepository)(nil)

func (r *MemoryRepository) ListTrash(ownerID string) ([]LifecycleFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := []LifecycleFile{}
	for _, f := range r.lifecycle {
		if f.OwnerID == ownerID && f.DeletedAt != nil && f.PurgedAt == nil {
			result = append(result, f)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DeletedAt.After(*result[j].DeletedAt) })
	return result, nil
}
func (r *MemoryRepository) MoveToTrash(ownerID, fileID string, now, purgeAfter time.Time) (LifecycleFile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.lifecycle[fileID]
	if !ok || f.OwnerID != ownerID || f.PurgedAt != nil {
		return LifecycleFile{}, ErrNotFound
	}
	if f.LegalHold {
		return LifecycleFile{}, ErrLegalHold
	}
	if f.RetentionUntil != nil && f.RetentionUntil.After(now) {
		return LifecycleFile{}, ErrRetentionActive
	}
	if f.DeletedAt != nil {
		return f, nil
	}
	f.DeletedAt, f.PurgeAfter = &now, &purgeAfter
	f.UpdatedAt = now
	r.lifecycle[fileID] = f
	r.files[fileID] = f.LogicalFile
	for id, grant := range r.grants {
		if grant.FileID == fileID && grant.RevokedAt == nil {
			grant.RevokedAt = &now
			r.grants[id] = grant
		}
	}
	return f, nil
}
func (r *MemoryRepository) RestoreFromTrash(ownerID, fileID string, now time.Time) (LifecycleFile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.lifecycle[fileID]
	if !ok || f.OwnerID != ownerID || f.DeletedAt == nil || f.PurgedAt != nil {
		return LifecycleFile{}, ErrNotInTrash
	}
	f.DeletedAt, f.PurgeAfter = nil, nil
	f.UpdatedAt = now
	r.lifecycle[fileID] = f
	r.files[fileID] = f.LogicalFile
	return f, nil
}
func (r *MemoryRepository) Purge(ownerID, fileID, operationID string, now time.Time) (PurgeResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.purges[operationID]; ok {
		if existing.FileID != fileID {
			return PurgeResult{}, errors.New("purge idempotency conflict")
		}
		return existing, nil
	}
	f, ok := r.lifecycle[fileID]
	if !ok || f.OwnerID != ownerID || f.DeletedAt == nil || f.PurgedAt != nil {
		return PurgeResult{}, ErrNotInTrash
	}
	if f.LegalHold {
		return PurgeResult{}, ErrLegalHold
	}
	if f.RetentionUntil != nil && f.RetentionUntil.After(now) {
		return PurgeResult{}, ErrRetentionActive
	}
	if f.PurgeAfter == nil || f.PurgeAfter.After(now) {
		return PurgeResult{}, ErrPurgeTooEarly
	}
	objects := []string{}
	destroyed := 0
	for id, m := range r.entries {
		for _, v := range r.versions[fileID] {
			if m.VersionID == v.VersionID && len(m.WrappedDEK) > 0 {
				objects = append(objects, m.BlobObject)
				m.WrappedDEK = nil
				r.entries[id] = m
				destroyed++
			}
		}
	}
	f.PurgedAt = &now
	f.UpdatedAt = now
	r.lifecycle[fileID] = f
	r.files[fileID] = f.LogicalFile
	for id, g := range r.grants {
		if g.FileID == fileID && g.RevokedAt == nil {
			g.RevokedAt = &now
			r.grants[id] = g
		}
	}
	result := PurgeResult{FileID: fileID, OperationID: operationID, DestroyedKeys: destroyed, CompletedAt: now, BlobObjects: objects}
	r.purges[operationID] = result
	r.deletions[operationID] = DeletionOperation{OperationID: operationID, FileID: fileID, OwnerID: ownerID, Status: "completed", DestroyedKeys: destroyed, Attempts: 1, CompletedAt: &now, UpdatedAt: now}
	return result, nil
}
func (r *MemoryRepository) SetRetention(fileID string, until *time.Time) (LifecycleFile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.lifecycle[fileID]
	if !ok || f.PurgedAt != nil {
		return LifecycleFile{}, ErrNotFound
	}
	if f.RetentionUntil != nil && (until == nil || until.Before(*f.RetentionUntil)) {
		return LifecycleFile{}, ErrRetentionActive
	}
	f.RetentionUntil = cloneTimeValue(until)
	r.lifecycle[fileID] = f
	return f, nil
}
func (r *MemoryRepository) SetLegalHold(fileID string, enabled bool, reason string) (LifecycleFile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.lifecycle[fileID]
	if !ok || f.PurgedAt != nil {
		return LifecycleFile{}, ErrNotFound
	}
	f.LegalHold, f.LegalHoldReason = enabled, reason
	if !enabled {
		f.LegalHoldReason = ""
	}
	r.lifecycle[fileID] = f
	return f, nil
}
func (r *MemoryRepository) LifecycleSummary(now time.Time, limit int) (LifecycleSummary, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := LifecycleSummary{}
	for _, f := range r.lifecycle {
		switch {
		case f.PurgedAt != nil:
			s.Purged++
		case f.DeletedAt != nil:
			s.Trashed++
		default:
			s.Active++
		}
		if f.PurgedAt == nil && f.RetentionUntil != nil && f.RetentionUntil.After(now) {
			s.Retained++
		}
		if f.PurgedAt == nil && f.LegalHold {
			s.Held++
		}
		if f.PurgedAt == nil && f.DeletedAt != nil && f.PurgeAfter != nil && !f.PurgeAfter.After(now) && !f.LegalHold && (f.RetentionUntil == nil || !f.RetentionUntil.After(now)) {
			s.EligibleForPurge++
		}
		s.Files = append(s.Files, f)
	}
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].UpdatedAt.After(s.Files[j].UpdatedAt) })
	if limit > 0 && len(s.Files) > limit {
		s.Files = s.Files[:limit]
	}
	for _, operation := range r.deletions {
		s.DeletionOperations = append(s.DeletionOperations, operation)
	}
	sort.Slice(s.DeletionOperations, func(i, j int) bool { return s.DeletionOperations[i].UpdatedAt.After(s.DeletionOperations[j].UpdatedAt) })
	s.RecoveryDrills = append(s.RecoveryDrills, r.drills...)
	return s, nil
}

func (r *MemoryRepository) EligibleForPurge(now time.Time, limit int) ([]LifecycleFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := []LifecycleFile{}
	for _, f := range r.lifecycle {
		if f.PurgedAt == nil && f.DeletedAt != nil && f.PurgeAfter != nil && !f.PurgeAfter.After(now) && !f.LegalHold && (f.RetentionUntil == nil || !f.RetentionUntil.After(now)) {
			result = append(result, f)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PurgeAfter.Before(*result[j].PurgeAfter) })
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (r *MemoryRepository) RecordDeletionFailure(ownerID, fileID, operationID, reason string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	op := r.deletions[operationID]
	op.OperationID, op.FileID, op.OwnerID, op.Status, op.ReasonCode, op.UpdatedAt = operationID, fileID, ownerID, "failed", reason, now
	op.Attempts++
	r.deletions[operationID] = op
	return nil
}

func (r *MemoryRepository) CurrentMetadataForDrill(fileID string) (Metadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.files[fileID]
	if !ok || r.lifecycle[fileID].PurgedAt != nil {
		return Metadata{}, ErrNotFound
	}
	for _, metadata := range r.entries {
		if metadata.VersionID == f.CurrentVersionID && len(metadata.WrappedDEK) > 0 {
			return cloneMetadata(metadata), nil
		}
	}
	return Metadata{}, ErrNotFound
}

func (r *MemoryRepository) RecordRecoveryDrill(drill RecoveryDrill) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drills = append([]RecoveryDrill{drill}, r.drills...)
	return nil
}

var _ LifecycleRepository = (*MemoryRepository)(nil)

func (r *MemoryRepository) ProtectedBlobObjects() ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	objects := make([]string, 0, len(r.entries))
	for _, metadata := range r.entries {
		if len(metadata.WrappedDEK) > 0 {
			objects = append(objects, metadata.BlobObject)
		}
	}
	sort.Strings(objects)
	return objects, nil
}

var _ capacityRepository = (*MemoryRepository)(nil)
