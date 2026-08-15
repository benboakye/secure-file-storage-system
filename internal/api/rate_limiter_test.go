package api

import (
	"testing"
	"time"
)

func TestAuthenticationRateLimiterUsesBoundedWindow(t *testing.T) {
	limiter := newAuthenticationRateLimiter(2, time.Minute)
	now := time.Date(2026, 8, 13, 19, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	firstAllowed := limiter.Allow("login", "127.0.0.1")
	secondAllowed := limiter.Allow("login", "127.0.0.1")
	if !firstAllowed || !secondAllowed {
		t.Fatal("allowed attempts rejected")
	}
	if limiter.Allow("login", "127.0.0.1") {
		t.Fatal("limit not enforced")
	}
	if !limiter.Allow("mfa", "127.0.0.1") {
		t.Fatal("independent endpoint scope was throttled")
	}
	now = now.Add(time.Minute + time.Second)
	if !limiter.Allow("login", "127.0.0.1") {
		t.Fatal("expired window did not reopen")
	}
}
