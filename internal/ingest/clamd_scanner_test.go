package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestClamdScannerStreamsQuarantineBytesAndMapsSafeVerdicts(t *testing.T) {
	tests := []struct {
		name, reply, wantReason string
		accepted                bool
		wantError               bool
	}{
		{name: "clean", reply: "stream: OK\x00", accepted: true, wantReason: "policy_accepted"},
		{name: "infected", reply: "stream: Unit-Test-Signature FOUND\x00", wantReason: "malware_detected"},
		{name: "daemon error", reply: "stream: scan engine unavailable ERROR\x00", wantError: true},
		{name: "malformed", reply: "unexpected\x00", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := []byte("harmless scanner protocol fixture")
			address := serveClamd(t, 2, func(connection net.Conn) {
				reader := bufio.NewReader(connection)
				command, _ := reader.ReadString(0)
				if command == "zVERSION\x00" {
					_, _ = connection.Write([]byte("ClamAV 1.4.3/27654/" + time.Now().UTC().Format(time.ANSIC) + "\x00"))
					return
				}
				if command != "zINSTREAM\x00" {
					t.Errorf("unexpected command %q", command)
					return
				}
				var streamed bytes.Buffer
				for {
					var size uint32
					if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
						t.Error(err)
						return
					}
					if size == 0 {
						break
					}
					if _, err := io.CopyN(&streamed, reader, int64(size)); err != nil {
						t.Error(err)
						return
					}
				}
				if !bytes.Equal(streamed.Bytes(), content) {
					t.Errorf("scanner received different bytes: %q", streamed.Bytes())
				}
				_, _ = connection.Write([]byte(test.reply))
			})
			path := writeScannerFixture(t, content)
			scanner, err := NewClamdScanner("tcp", address, 1024, time.Second, time.Second, 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			result, err := scanner.Inspect(t.Context(), Evidence{Name: "fixture.bin", QuarantinePath: path})
			if test.wantError {
				if err == nil {
					t.Fatalf("unsafe daemon response was accepted: %#v", result)
				}
				return
			}
			if err != nil || result.Accepted != test.accepted || result.Reason != test.wantReason || result.Tool != "clamd-instream" {
				t.Fatalf("unexpected verdict: %#v err=%v", result, err)
			}
		})
	}
}

func TestClamdScannerFailsClosedOnLimitsAndTimeout(t *testing.T) {
	content := []byte("four")
	address := serveClamd(t, 2, func(connection net.Conn) {
		reader := bufio.NewReader(connection)
		command, _ := reader.ReadString(0)
		if command == "zVERSION\x00" {
			_, _ = connection.Write([]byte("ClamAV 1.4.3/27654/" + time.Now().UTC().Format(time.ANSIC) + "\x00"))
			return
		}
		time.Sleep(100 * time.Millisecond)
	})
	scanner, err := NewClamdScanner("tcp", address, 3, time.Second, 25*time.Millisecond, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Inspect(context.Background(), Evidence{QuarantinePath: writeScannerFixture(t, content)}); err == nil {
		t.Fatal("oversized stream did not fail closed")
	}

	timeoutAddress := serveClamd(t, 2, func(connection net.Conn) {
		reader := bufio.NewReader(connection)
		command, _ := reader.ReadString(0)
		if command == "zVERSION\x00" {
			_, _ = connection.Write([]byte("ClamAV 1.4.3/27654/" + time.Now().UTC().Format(time.ANSIC) + "\x00"))
			return
		}
		time.Sleep(100 * time.Millisecond)
	})
	timeoutScanner, _ := NewClamdScanner("tcp", timeoutAddress, 1024, time.Second, 20*time.Millisecond, 24*time.Hour)
	if _, err := timeoutScanner.Inspect(context.Background(), Evidence{QuarantinePath: writeScannerFixture(t, []byte("bounded"))}); err == nil {
		t.Fatal("scanner timeout did not fail closed")
	}
}

func TestClamdPostureReflectsLivePingWithoutExposingAddress(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	address := serveClamd(t, 2, func(connection net.Conn) {
		reader := bufio.NewReader(connection)
		command, _ := reader.ReadString(0)
		switch command {
		case "zPING\x00":
			_, _ = connection.Write([]byte("PONG\x00"))
		case "zVERSION\x00":
			_, _ = connection.Write([]byte("ClamAV 1.4.3/27654/Thu Aug 13 11:30:00 2026\x00"))
		}
	})
	scanner, _ := NewClamdScanner("tcp", address, 1024, time.Second, time.Second, 24*time.Hour)
	scanner.now = func() time.Time { return now }
	posture := scanner.Posture()
	if !posture.Connected || !posture.ProductionReady || !posture.FailClosed || !posture.SignaturesFresh || posture.Adapter != "clamd-instream" || posture.EngineVersion != "1.4.3" || posture.SignatureDB != "27654" || posture.SignatureAgeSeconds != 1800 || posture.SignatureMaxAgeSeconds != 86400 {
		t.Fatalf("healthy daemon posture was inaccurate: %#v", posture)
	}
	if bytes.Contains([]byte(posture.Detail), []byte(address)) {
		t.Fatal("scanner posture exposed the daemon address")
	}
}

func TestClamdStaleSignaturesFailPostureAndInspectionClosed(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	address := serveClamd(t, 3, func(connection net.Conn) {
		reader := bufio.NewReader(connection)
		command, _ := reader.ReadString(0)
		switch command {
		case "zPING\x00":
			_, _ = connection.Write([]byte("PONG\x00"))
		case "zVERSION\x00":
			_, _ = connection.Write([]byte("ClamAV 1.4.3/27600/Tue Aug 11 12:00:00 2026\x00"))
		default:
			t.Errorf("stale scanner received unsafe command %q", command)
		}
	})
	scanner, err := NewClamdScanner("tcp", address, 1024, time.Second, time.Second, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	scanner.now = func() time.Time { return now }
	posture := scanner.Posture()
	if !posture.Connected || posture.ProductionReady || posture.SignaturesFresh || posture.SignatureAgeSeconds != 48*60*60 {
		t.Fatalf("stale signature posture was inaccurate: %#v", posture)
	}
	if _, err := scanner.Inspect(t.Context(), Evidence{QuarantinePath: writeScannerFixture(t, []byte("not scanned"))}); err == nil {
		t.Fatal("stale signature database did not fail inspection closed")
	}
}

func TestParseClamdVersionRejectsMissingAndFutureTimestampEvidence(t *testing.T) {
	if _, _, _, ok := parseClamdVersion("ClamAV 1.4.3/27654"); ok {
		t.Fatal("version without signature timestamp was accepted")
	}
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	address := serveClamdOnce(t, func(connection net.Conn) {
		reader := bufio.NewReader(connection)
		command, _ := reader.ReadString(0)
		if command != "zVERSION\x00" {
			t.Errorf("unexpected command %q", command)
			return
		}
		_, _ = connection.Write([]byte("ClamAV 1.4.3/27654/Thu Aug 13 12:10:00 2026\x00"))
	})
	scanner, err := NewClamdScanner("tcp", address, 1024, time.Second, time.Second, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, updatedAt, fresh := scanner.signatureStatus(t.Context(), now)
	if updatedAt == nil || fresh {
		t.Fatalf("future signature timestamp was accepted: updated=%v fresh=%v", updatedAt, fresh)
	}
}

func TestIngestionFailsClosedWhenClamdIsUnavailable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	scanner, err := NewClamdScanner("tcp", address, 1024, 25*time.Millisecond, 25*time.Millisecond, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Config{QuarantineDir: t.TempDir(), MaxUploadBytes: 1024, InspectionTTL: 100 * time.Millisecond, Scanner: scanner})
	if err != nil {
		t.Fatal(err)
	}
	upload, _, err := manager.Create(t.Context(), "usr_clamd", "idem-clamd-down", "report.pdf", "application/pdf", bytes.NewBufferString("harmless fixture"))
	if err != nil {
		t.Fatal(err)
	}
	terminal := waitForTerminal(t, manager, "usr_clamd", upload.ID)
	if terminal.Status != StatusFailed || terminal.DecisionReason != "inspection_unavailable" {
		t.Fatalf("unavailable production scanner did not fail closed: %#v", terminal)
	}
}

func serveClamdOnce(t *testing.T, handler func(net.Conn)) string {
	return serveClamd(t, 1, handler)
}

func serveClamd(t *testing.T, connections int, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for range connections {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			handler(connection)
			_ = connection.Close()
		}
	}()
	return listener.Addr().String()
}

func writeScannerFixture(t *testing.T, content []byte) string {
	t.Helper()
	path := t.TempDir() + string(os.PathSeparator) + "quarantine-object"
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
