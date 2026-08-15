package ingest

import (
	"context"
	"strings"
	"time"
)

type DeterministicScanner struct {
	Delay time.Duration
}

func (DeterministicScanner) Posture() ScannerPosture {
	return ScannerPosture{
		Connected: true, ProductionReady: false, FailClosed: true,
		Adapter: "deterministic-test-scanner", PolicyVersion: "v1.4-demo",
		Detail: "Development policy adapter; no malware signature engine is connected.",
	}
}

func (scanner DeterministicScanner) Inspect(ctx context.Context, evidence Evidence) (ScanResult, error) {
	if scanner.Delay > 0 {
		timer := time.NewTimer(scanner.Delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ScanResult{}, ErrScannerFailure
		case <-timer.C:
		}
	}

	name := strings.ToLower(evidence.Name)
	if strings.Contains(name, "timeout") || strings.Contains(name, "scanner-error") {
		return ScanResult{}, ErrScannerFailure
	}
	if strings.Contains(name, "blocked") || strings.Contains(name, "rejected") || strings.HasSuffix(name, ".exe") {
		return ScanResult{Accepted: false, Reason: "disallowed_content", Tool: "deterministic-test-scanner", Policy: "v1.4-demo"}, nil
	}
	return ScanResult{Accepted: true, Reason: "policy_accepted", Tool: "deterministic-test-scanner", Policy: "v1.4-demo"}, nil
}
