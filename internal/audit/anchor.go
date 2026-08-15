package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrAnchorUnavailable = errors.New("audit checkpoint anchor is unavailable")

type AnchorRecord struct {
	ChainID    string `json:"chainId"`
	Sequence   int64  `json:"sequence"`
	Checkpoint string `json:"checkpoint"`
	// PreviousCheckpoint lets an independent ledger enforce that a new receipt
	// extends its retained chain head instead of accepting an unrelated fork.
	// Local historical records omit it and retain their original HMAC format.
	PreviousCheckpoint string    `json:"previousCheckpoint,omitempty"`
	KeyVersion         string    `json:"keyVersion"`
	AnchoredAt         time.Time `json:"anchoredAt"`
	Signature          string    `json:"signature,omitempty"`
}

type AnchorPosture struct {
	Connected       bool   `json:"connected"`
	ProductionReady bool   `json:"productionReady"`
	Adapter         string `json:"adapter"`
	Detail          string `json:"detail"`
}

type CheckpointAnchor interface {
	Append(AnchorRecord) error
	Latest() (AnchorRecord, error)
	Posture() AnchorPosture
}

// anchorReceiptVerifier marks an adapter whose receipts are signed by an
// external trust boundary. SecureStore verifies those receipts with pinned
// public material and therefore does not need the remote signing secret.
type anchorReceiptVerifier interface {
	VerifyReceipt(AnchorRecord) bool
}

// FileCheckpointAnchor is an append-only development adapter. It proves the
// anchor protocol locally but is not independent from the application host.
type FileCheckpointAnchor struct {
	path string
	mu   sync.Mutex
}

func NewFileCheckpointAnchor(path string) (*FileCheckpointAnchor, error) {
	if path == "" {
		return nil, ErrAnchorUnavailable
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return &FileCheckpointAnchor{path: path}, nil
}

func (a *FileCheckpointAnchor) Append(record AnchorRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(a.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func (a *FileCheckpointAnchor) Latest() (AnchorRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	file, err := os.Open(a.path)
	if err != nil {
		return AnchorRecord{}, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var latest AnchorRecord
	found := false
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			var record AnchorRecord
			if err := json.Unmarshal(line, &record); err != nil {
				return AnchorRecord{}, ErrAnchorUnavailable
			}
			latest, found = record, true
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return AnchorRecord{}, readErr
		}
	}
	if !found {
		return AnchorRecord{}, ErrAnchorUnavailable
	}
	return latest, nil
}

func (a *FileCheckpointAnchor) Posture() AnchorPosture {
	return AnchorPosture{Connected: true, ProductionReady: false, Adapter: "append-only-local-file", Detail: "Signed checkpoints are stored outside PostgreSQL, but remain on the application host. Production requires an independent append-only service."}
}

func signAnchor(key []byte, record AnchorRecord) string {
	mac := hmac.New(sha256.New, key)
	writeField(mac, []byte("securestore.audit.anchor.v1"))
	writeField(mac, []byte(record.ChainID))
	_ = binary.Write(mac, binary.BigEndian, record.Sequence)
	writeField(mac, []byte(record.Checkpoint))
	writeField(mac, []byte(record.KeyVersion))
	writeField(mac, []byte(record.AnchoredAt.UTC().Format(time.RFC3339Nano)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validAnchorSignature(key []byte, record AnchorRecord) bool {
	provided, err := base64.RawURLEncoding.DecodeString(record.Signature)
	if err != nil {
		return false
	}
	record.Signature = ""
	expected, err := base64.RawURLEncoding.DecodeString(signAnchor(key, record))
	return err == nil && hmac.Equal(provided, expected)
}
