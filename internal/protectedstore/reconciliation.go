package protectedstore

import (
	"errors"
	"time"

	"securestore/internal/auditoutbox"
	"securestore/internal/orphan"
)

const (
	ReconciliationAuthorized = "authorized"
	ReconciliationCompleted  = "completed"
	ReconciliationFailed     = "failed"
)

// OrphanReconciliationOperation is the durable hand-off between an
// administrator request and filesystem deletion. StorageObject is deliberately
// excluded from JSON so paths and internal object names cannot reach clients.
type OrphanReconciliationOperation struct {
	OperationID   string     `json:"operationId"`
	Token         string     `json:"token"`
	Zone          string     `json:"zone"`
	StorageObject string     `json:"-"`
	Size          int64      `json:"size"`
	ModifiedAt    time.Time  `json:"modifiedAt"`
	ActorID       string     `json:"actorId"`
	CorrelationID string     `json:"correlationId"`
	Status        string     `json:"status"`
	ReasonCode    string     `json:"reasonCode"`
	AuthorizedAt  time.Time  `json:"authorizedAt"`
	CompletedAt   *time.Time `json:"completedAt,omitempty"`
}

type orphanReconciliationRepository interface {
	AuthorizeOrphanReconciliation(OrphanReconciliationOperation, auditoutbox.Intent) (OrphanReconciliationOperation, bool, error)
	CompleteOrphanReconciliation(string, string, string, time.Time, auditoutbox.Intent) (bool, error)
	PendingOrphanReconciliations(int) ([]OrphanReconciliationOperation, error)
}

func (s *Service) AuthorizeOrphanReconciliation(candidate orphan.Candidate, actorID, correlationID string, intent auditoutbox.Intent) (OrphanReconciliationOperation, bool, error) {
	repository, ok := s.repository.(orphanReconciliationRepository)
	if !ok || candidate.StorageObject == "" || (candidate.Zone != "quarantine" && candidate.Zone != "protected") {
		return OrphanReconciliationOperation{}, false, ErrNotFound
	}
	id, err := opaqueID("reconcile")
	if err != nil {
		return OrphanReconciliationOperation{}, false, err
	}
	operation := OrphanReconciliationOperation{
		OperationID: id, Token: candidate.Token, Zone: candidate.Zone,
		StorageObject: candidate.StorageObject, Size: candidate.Size,
		ModifiedAt: candidate.ModifiedAt.UTC().Truncate(time.Microsecond),
		ActorID:    actorID, CorrelationID: correlationID, Status: ReconciliationAuthorized,
		ReasonCode: "administrator_reconciliation", AuthorizedAt: s.now().UTC().Truncate(time.Microsecond),
	}
	return repository.AuthorizeOrphanReconciliation(operation, intent)
}

func (s *Service) CompleteOrphanReconciliation(operationID, status, reasonCode string, intent auditoutbox.Intent) (bool, error) {
	if status != ReconciliationCompleted && status != ReconciliationFailed {
		return false, errors.New("invalid reconciliation completion status")
	}
	repository, ok := s.repository.(orphanReconciliationRepository)
	if !ok {
		return false, ErrNotFound
	}
	return repository.CompleteOrphanReconciliation(operationID, status, reasonCode, s.now().UTC().Truncate(time.Microsecond), intent)
}

func (s *Service) PendingOrphanReconciliations(limit int) ([]OrphanReconciliationOperation, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("reconciliation limit must be between 1 and 100")
	}
	repository, ok := s.repository.(orphanReconciliationRepository)
	if !ok {
		return nil, ErrNotFound
	}
	return repository.PendingOrphanReconciliations(limit)
}

func (s *Service) ResumeProtectedOrphan(operation OrphanReconciliationOperation) (orphan.ResumeOutcome, error) {
	repository, ok := s.repository.(reconciliationRepository)
	if !ok || operation.Zone != "protected" {
		return orphan.ResumeOutcome{}, ErrNotFound
	}
	return orphan.Resume(s.rootDir, operation.StorageObject, operation.Size, operation.ModifiedAt, repository.ProtectedBlobObjectExists)
}
