package protectedstore

import (
	"bytes"
	"errors"
	"time"

	"securestore/internal/auditoutbox"
)

const maxDEKRewrapBatch = 100

// KeyRotationPosture reports only safe aggregate metadata. It never exposes a
// wrapped DEK, KEK material, file name, owner identity, or ciphertext path.
type KeyRotationPosture struct {
	CurrentKEKID      string `json:"currentKekId"`
	CurrentKEKVersion string `json:"currentKekVersion"`
	ProtectedVersions int    `json:"protectedVersions"`
	CurrentVersions   int    `json:"currentVersions"`
	PendingVersions   int    `json:"pendingVersions"`
	CompletedRewraps  int    `json:"completedRewraps"`
	Durable           bool   `json:"durable"`
}

type DEKRewrapResult struct {
	Requested int                  `json:"requested"`
	Completed int                  `json:"completed"`
	Skipped   int                  `json:"skipped"`
	Failed    int                  `json:"failed"`
	Remaining int                  `json:"remaining"`
	Intents   []auditoutbox.Intent `json:"-"`
	Durable   bool                 `json:"-"`
}

type rewrapRepository interface {
	KeyRotationPosture(currentID, currentVersion string) (KeyRotationPosture, error)
	ListDEKRewrapCandidates(currentID, currentVersion string, limit int) ([]Metadata, error)
	CommitDEKRewrap(candidate Metadata, replacement []byte, targetID, targetVersion, operationID string, attemptedAt time.Time, intent auditoutbox.Intent) (bool, error)
}

type RewrapIntentFactory func(Metadata, string, string, string, string) (auditoutbox.Intent, error)

func (s *Service) KeyRotationPosture() (KeyRotationPosture, error) {
	repository, ok := s.repository.(rewrapRepository)
	if !ok {
		return KeyRotationPosture{CurrentKEKID: s.keys.ID(), CurrentKEKVersion: s.keys.Version(), Durable: false}, nil
	}
	return repository.KeyRotationPosture(s.keys.ID(), s.keys.Version())
}

// RewrapDEKs rotates only encrypted DEK wrappers. It never opens protected
// ciphertext and therefore cannot expose or rewrite user file content.
func (s *Service) RewrapDEKs(limit int, factory RewrapIntentFactory) (DEKRewrapResult, error) {
	if limit <= 0 || limit > maxDEKRewrapBatch || factory == nil {
		return DEKRewrapResult{}, errors.New("invalid DEK rewrap request")
	}
	repository, ok := s.repository.(rewrapRepository)
	if !ok {
		return DEKRewrapResult{}, errors.New("DEK rewrap repository is unavailable")
	}
	candidates, err := repository.ListDEKRewrapCandidates(s.keys.ID(), s.keys.Version(), limit)
	if err != nil {
		return DEKRewrapResult{}, err
	}
	result := DEKRewrapResult{Requested: len(candidates), Durable: s.repository.Durable()}
	for _, candidate := range candidates {
		fromID, fromVersion := wrappingKeyIdentity(candidate)
		dek, unwrapErr := s.keys.Unwrap(candidate.WrappedDEK, fromID, fromVersion)
		if unwrapErr != nil {
			result.Failed++
			continue
		}
		replacement, wrapErr := s.keys.Wrap(dek)
		clear(dek)
		if wrapErr != nil {
			result.Failed++
			continue
		}
		intent, intentErr := factory(candidate, fromID, fromVersion, s.keys.ID(), s.keys.Version())
		if intentErr != nil {
			return result, intentErr
		}
		operationID, idErr := opaqueID("rewrap")
		if idErr != nil {
			return result, idErr
		}
		committed, commitErr := repository.CommitDEKRewrap(candidate, replacement, s.keys.ID(), s.keys.Version(), operationID, s.now().UTC(), intent)
		clear(replacement)
		if commitErr != nil {
			return result, commitErr
		}
		if !committed {
			result.Skipped++
			continue
		}
		result.Completed++
		result.Intents = append(result.Intents, intent)
	}
	posture, err := repository.KeyRotationPosture(s.keys.ID(), s.keys.Version())
	if err != nil {
		return result, err
	}
	result.Remaining = posture.PendingVersions
	return result, nil
}

func sameWrappedDEK(left, right []byte) bool { return bytes.Equal(left, right) }
