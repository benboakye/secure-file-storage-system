package api

import (
	"crypto/sha256"
	"sync"
	"time"
)

// authenticationRateLimiter is deliberately local to one API process. It
// protects the prototype boundary from short bursts; a distributed deployment
// must replace it with a shared limiter at the trusted ingress layer.
type authenticationRateLimiter struct {
	mu       sync.Mutex
	attempts map[[32]byte][]time.Time
	limit    int
	window   time.Duration
	now      func() time.Time
}

func newAuthenticationRateLimiter(limit int, window time.Duration) *authenticationRateLimiter {
	return &authenticationRateLimiter{attempts: make(map[[32]byte][]time.Time), limit: limit, window: window, now: time.Now}
}

func (limiter *authenticationRateLimiter) Allow(scope, networkAddress string) bool {
	key := sha256.Sum256([]byte(scope + "\x00" + networkAddress))
	now := limiter.now().UTC()
	cutoff := now.Add(-limiter.window)
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	values := limiter.attempts[key]
	kept := values[:0]
	for _, value := range values {
		if value.After(cutoff) {
			kept = append(kept, value)
		}
	}
	if len(kept) >= limiter.limit {
		limiter.attempts[key] = kept
		return false
	}
	limiter.attempts[key] = append(kept, now)
	return true
}
