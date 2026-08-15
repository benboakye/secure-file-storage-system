package api

import (
	"testing"
	"time"
)

func TestTelemetryPostureRequiresRecentAuthenticatedScrape(t *testing.T) {
	if _, err := newTelemetryRegistry("too-short", time.Minute); err == nil {
		t.Fatal("weak metrics token was accepted")
	}
	registry, err := newTelemetryRegistry("telemetry-test-token-with-at-least-32-bytes", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 13, 22, 0, 0, 0, time.UTC)
	if posture := registry.posture(now); !posture.ExporterEnabled || posture.Connected || posture.ScrapesTotal != 0 {
		t.Fatalf("enabled exporter overstated collector activity: %#v", posture)
	}
	registry.recordScrape(now)
	if posture := registry.posture(now.Add(30 * time.Second)); !posture.Connected || posture.ScrapesTotal != 1 || posture.LastScrapeAt == nil {
		t.Fatalf("recent scrape was not reported: %#v", posture)
	}
	if posture := registry.posture(now.Add(2 * time.Minute)); posture.Connected {
		t.Fatalf("stale scraper was reported connected: %#v", posture)
	}
}

func TestDisabledTelemetryHasNoAuthenticationSurface(t *testing.T) {
	registry, err := newTelemetryRegistry("", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if registry.enabled || registry.authorized("Bearer anything") {
		t.Fatal("disabled exporter accepted a bearer credential")
	}
}
