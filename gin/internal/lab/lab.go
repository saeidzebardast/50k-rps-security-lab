// Package lab holds the pieces both Gin builds share.
package lab

import (
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Password hash for user "alice", computed once at start-up.
var AliceHash, _ = bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), 10)

// Limiter is a fixed-window counter. Good enough for a lab; use your edge or
// a shared store in production.
type Limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*entry
}

type entry struct {
	start time.Time
	n     int
}

func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{limit: limit, window: window, hits: map[string]*entry{}}
}

// Limited records a hit for key and reports whether it is over the limit.
func (l *Limiter) Limited(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.hits[key]
	if !ok || now.Sub(e.start) > l.window {
		l.hits[key] = &entry{start: now, n: 1}
		return false
	}
	e.n++
	return e.n > l.limit
}

type Credentials struct {
	Username string `json:"username" binding:"max=64"`
	Password string `json:"password" binding:"max=128"`
}
