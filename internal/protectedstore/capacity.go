package protectedstore

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"securestore/internal/orphan"
)

// CapacitySummary contains metadata-only storage evidence. It never opens,
// decrypts, hashes, or returns the names of protected objects.
type CapacitySummary struct {
	TrackedObjects         int             `json:"trackedObjects"`
	TrackedCiphertextBytes int64           `json:"trackedCiphertextBytes"`
	OrphanedObjects        int             `json:"orphanedObjects"`
	OrphanedBytes          int64           `json:"orphanedBytes"`
	MissingObjects         int             `json:"missingObjects"`
	VolumeTotalBytes       uint64          `json:"volumeTotalBytes"`
	VolumeAvailableBytes   uint64          `json:"volumeAvailableBytes"`
	VolumeUsedPercent      float64         `json:"volumeUsedPercent"`
	Alerts                 []CapacityAlert `json:"alerts"`
}

type CapacityAlert struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Count    int    `json:"count"`
}

type capacityRepository interface {
	ProtectedBlobObjects() ([]string, error)
}

type reconciliationRepository interface {
	ProtectedBlobObjects() ([]string, error)
	ProtectedBlobObjectExists(string) (bool, error)
}

func (s *Service) OrphanCandidates(minimumAge time.Duration) ([]orphan.Candidate, error) {
	repository, ok := s.repository.(capacityRepository)
	if !ok {
		return nil, ErrNotFound
	}
	objects, err := repository.ProtectedBlobObjects()
	if err != nil {
		return nil, err
	}
	tracked := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		tracked[object] = struct{}{}
	}
	return orphan.List(s.rootDir, "protected", tracked, minimumAge, s.now().UTC())
}

func (s *Service) DeleteOrphan(token string, minimumAge time.Duration) (orphan.Candidate, error) {
	repository, ok := s.repository.(reconciliationRepository)
	if !ok {
		return orphan.Candidate{}, ErrNotFound
	}
	objects, err := repository.ProtectedBlobObjects()
	if err != nil {
		return orphan.Candidate{}, err
	}
	tracked := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		tracked[object] = struct{}{}
	}
	deleted, err := orphan.Delete(s.rootDir, "protected", tracked, token, minimumAge, s.now().UTC(), repository.ProtectedBlobObjectExists)
	if errors.Is(err, orphan.ErrNotFound) {
		return orphan.Candidate{}, ErrNotFound
	}
	return deleted, err
}

func (s *Service) CapacitySummary() (CapacitySummary, error) {
	repository, ok := s.repository.(capacityRepository)
	if !ok {
		return CapacitySummary{}, ErrNotFound
	}
	objects, err := repository.ProtectedBlobObjects()
	if err != nil {
		return CapacitySummary{}, err
	}
	known := make(map[string]bool, len(objects))
	for _, object := range objects {
		known[object] = false
	}
	summary := CapacitySummary{Alerts: []CapacityAlert{}}
	entries, err := os.ReadDir(s.rootDir)
	if err != nil {
		return CapacitySummary{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return CapacitySummary{}, err
		}
		if _, tracked := known[entry.Name()]; tracked {
			known[entry.Name()] = true
			summary.TrackedObjects++
			summary.TrackedCiphertextBytes += info.Size()
		} else {
			summary.OrphanedObjects++
			summary.OrphanedBytes += info.Size()
		}
	}
	for _, present := range known {
		if !present {
			summary.MissingObjects++
		}
	}
	total, available, err := filesystemCapacity(filepath.Clean(s.rootDir))
	if err != nil {
		return CapacitySummary{}, err
	}
	summary.VolumeTotalBytes, summary.VolumeAvailableBytes = total, available
	if total > 0 {
		summary.VolumeUsedPercent = float64(total-available) * 100 / float64(total)
	}
	if summary.MissingObjects > 0 {
		summary.Alerts = append(summary.Alerts, CapacityAlert{ID: "protected-objects-missing", Severity: "high", Title: "Protected objects missing", Detail: "Database metadata refers to ciphertext that is absent from protected storage.", Count: summary.MissingObjects})
	}
	if summary.OrphanedObjects > 0 {
		summary.Alerts = append(summary.Alerts, CapacityAlert{ID: "protected-objects-orphaned", Severity: "medium", Title: "Unmatched protected objects", Detail: "Ciphertext exists without active protected-version metadata; no automatic deletion was attempted.", Count: summary.OrphanedObjects})
	}
	if total > 0 && available < total/10 {
		summary.Alerts = append(summary.Alerts, CapacityAlert{ID: "protected-volume-low", Severity: "high", Title: "Protected-storage volume is nearly full", Detail: "Less than ten percent of the hosting volume is available.", Count: 1})
	}
	sort.Slice(summary.Alerts, func(i, j int) bool { return summary.Alerts[i].ID < summary.Alerts[j].ID })
	return summary, nil
}
