package ingest

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const (
	clamdChunkBytes   = 64 * 1024
	clamdMaxReplySize = 8 * 1024
)

// ClamdScanner submits the exact quarantine bytes with ClamAV's INSTREAM
// protocol. It never asks the daemon to open an application path, which keeps
// the integration valid across containers and prevents path interpretation at
// the scanner trust boundary.
type ClamdScanner struct {
	Network, Address string
	MaxStreamBytes   int64
	DialTimeout      time.Duration
	IOTimeout        time.Duration
	MaxSignatureAge  time.Duration
	now              func() time.Time
}

func NewClamdScanner(network, address string, maxStreamBytes int64, dialTimeout, ioTimeout, maxSignatureAge time.Duration) (*ClamdScanner, error) {
	if network != "tcp" && network != "unix" {
		return nil, errors.New("clamd network must be tcp or unix")
	}
	if strings.TrimSpace(address) == "" || maxStreamBytes <= 0 || dialTimeout <= 0 || ioTimeout <= 0 || maxSignatureAge <= 0 {
		return nil, errors.New("invalid clamd configuration")
	}
	return &ClamdScanner{
		Network: network, Address: address, MaxStreamBytes: maxStreamBytes,
		DialTimeout: dialTimeout, IOTimeout: ioTimeout, MaxSignatureAge: maxSignatureAge,
		now: time.Now,
	}, nil
}

func (s *ClamdScanner) Inspect(ctx context.Context, evidence Evidence) (ScanResult, error) {
	// A responsive daemon with stale definitions is not a trustworthy policy
	// decision point. VERSION is checked immediately before INSTREAM so stale,
	// missing, malformed, or future-dated signature evidence fails closed.
	_, signatures, _, fresh := s.signatureStatus(ctx, s.now().UTC())
	if !fresh {
		return ScanResult{}, ErrScannerFailure
	}
	if evidence.QuarantinePath == "" {
		return ScanResult{}, ErrScannerFailure
	}
	file, err := os.Open(evidence.QuarantinePath)
	if err != nil {
		return ScanResult{}, ErrScannerFailure
	}
	defer file.Close()

	connection, err := s.dial(ctx)
	if err != nil {
		return ScanResult{}, ErrScannerFailure
	}
	defer connection.Close()
	if err := writeAll(connection, []byte("zINSTREAM\x00")); err != nil {
		return ScanResult{}, ErrScannerFailure
	}
	buffer := make([]byte, clamdChunkBytes)
	var streamed int64
	for {
		read, readErr := file.Read(buffer)
		if read > 0 {
			streamed += int64(read)
			if streamed > s.MaxStreamBytes || writeChunk(connection, buffer[:read]) != nil {
				return ScanResult{}, ErrScannerFailure
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return ScanResult{}, ErrScannerFailure
		}
	}
	if writeChunk(connection, nil) != nil {
		return ScanResult{}, ErrScannerFailure
	}
	reply, err := readClamdRecord(connection)
	if err != nil {
		return ScanResult{}, ErrScannerFailure
	}
	switch {
	case strings.HasSuffix(reply, ": OK"):
		return ScanResult{Accepted: true, Reason: "policy_accepted", Tool: "clamd-instream", Policy: "clamav-db-" + signatures}, nil
	case strings.HasSuffix(reply, " FOUND"):
		// Signature names are intentionally not persisted. They may be sensitive,
		// unstable, or include unsafe daemon-controlled text.
		return ScanResult{Accepted: false, Reason: "malware_detected", Tool: "clamd-instream", Policy: "clamav-db-" + signatures}, nil
	default:
		return ScanResult{}, ErrScannerFailure
	}
}

func (s *ClamdScanner) Posture() ScannerPosture {
	checkedAt := s.now().UTC()
	pingContext, cancelPing := context.WithTimeout(context.Background(), s.DialTimeout+s.IOTimeout)
	reply, err := s.command(pingContext, "PING")
	cancelPing()
	connected := err == nil && reply == "PONG"
	detail := "ClamAV daemon is unavailable; uploads fail closed before protected storage."
	posture := ScannerPosture{
		Connected: connected, FailClosed: true, Adapter: "clamd-instream",
		PolicyVersion: "clamav-signatures", SignatureMaxAgeSeconds: int64(s.MaxSignatureAge.Seconds()),
		CheckedAt: &checkedAt, Detail: detail,
	}
	if !connected {
		return posture
	}
	versionContext, cancelVersion := context.WithTimeout(context.Background(), s.DialTimeout+s.IOTimeout)
	engine, signatures, updatedAt, fresh := s.signatureStatus(versionContext, checkedAt)
	cancelVersion()
	if updatedAt == nil {
		posture.Detail = "ClamAV responds to health checks, but signed database timestamp evidence is unavailable; uploads fail closed."
		return posture
	}
	posture.SignatureUpdatedAt = updatedAt
	posture.SignatureAgeSeconds = max(0, int64(checkedAt.Sub(*updatedAt).Seconds()))
	posture.SignaturesFresh = fresh
	posture.ProductionReady = fresh
	posture.EngineVersion, posture.SignatureDB = engine, signatures
	posture.PolicyVersion = "clamav-db-" + signatures
	if !fresh {
		posture.Detail = "ClamAV is reachable, but signature timestamp evidence is stale or invalid; uploads fail closed."
		return posture
	}
	posture.Detail = "ClamAV health and fresh signature timestamp evidence are available; quarantined bytes use bounded INSTREAM scanning."
	return posture
}

func (s *ClamdScanner) signatureStatus(ctx context.Context, now time.Time) (string, string, *time.Time, bool) {
	reply, err := s.command(ctx, "VERSION")
	if err != nil {
		return "", "", nil, false
	}
	engine, signatures, updatedAt, ok := parseClamdVersion(reply)
	if !ok {
		return "", "", nil, false
	}
	age := now.Sub(updatedAt)
	// A small future skew is tolerated for container clock synchronization;
	// larger future timestamps are invalid evidence rather than "fresh" data.
	fresh := age >= -5*time.Minute && age <= s.MaxSignatureAge
	return engine, signatures, &updatedAt, fresh
}

func parseClamdVersion(reply string) (string, string, time.Time, bool) {
	if !strings.HasPrefix(reply, "ClamAV ") {
		return "", "", time.Time{}, false
	}
	parts := strings.Split(strings.TrimPrefix(reply, "ClamAV "), "/")
	if len(parts) != 3 || !safeVersionToken(parts[0]) || !safeVersionToken(parts[1]) || len(parts[2]) > 64 {
		return "", "", time.Time{}, false
	}
	for _, layout := range []string{time.ANSIC, "Mon Jan _2 2006"} {
		updatedAt, err := time.ParseInLocation(layout, strings.TrimSpace(parts[2]), time.UTC)
		if err == nil {
			return parts[0], parts[1], updatedAt.UTC(), true
		}
	}
	return "", "", time.Time{}, false
}

func safeVersionToken(value string) bool {
	if value == "" || len(value) > 40 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("._+-", character) {
			continue
		}
		return false
	}
	return true
}

func (s *ClamdScanner) command(ctx context.Context, command string) (string, error) {
	connection, err := s.dial(ctx)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if err := writeAll(connection, append([]byte("z"+command), 0)); err != nil {
		return "", err
	}
	return readClamdRecord(connection)
}

func (s *ClamdScanner) dial(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: s.DialTimeout}
	connection, err := dialer.DialContext(ctx, s.Network, s.Address)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(s.IOTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func writeChunk(destination io.Writer, chunk []byte) error {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(chunk)))
	if err := writeAll(destination, length[:]); err != nil {
		return err
	}
	if len(chunk) > 0 {
		return writeAll(destination, chunk)
	}
	return nil
}

func writeAll(destination io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := destination.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func readClamdRecord(source io.Reader) (string, error) {
	limited := io.LimitReader(source, clamdMaxReplySize+1)
	record, err := bufio.NewReader(limited).ReadString(0)
	if err != nil || len(record) > clamdMaxReplySize || !strings.HasSuffix(record, "\x00") {
		return "", ErrScannerFailure
	}
	return strings.TrimSuffix(record, "\x00"), nil
}

var _ Scanner = (*ClamdScanner)(nil)
var _ scannerPostureReporter = (*ClamdScanner)(nil)
