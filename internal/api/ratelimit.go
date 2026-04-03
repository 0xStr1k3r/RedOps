package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a fixed-window per-IP limiter for brute-force-sensitive
// endpoints (login/register). Same-process memory is sufficient: secrets live
// in one process and horizontal scaling is out of scope for the lab build.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
	calls  int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: map[string][]time.Time{}, limit: limit, window: window}
}

func (l *rateLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// Opportunistic sweep bounds memory against IP-cycling floods.
	if l.calls++; l.calls%1000 == 0 {
		for k, v := range l.hits {
			keep := v[:0]
			for _, t := range v {
				if now.Sub(t) < l.window {
					keep = append(keep, t)
				}
			}
			if len(keep) == 0 {
				delete(l.hits, k)
			} else {
				l.hits[k] = keep
			}
		}
	}
	recent := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.limit {
		l.hits[ip] = recent
		return false
	}
	l.hits[ip] = append(recent, now)
	return true
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// limitAuth wraps login/register: 10 attempts/minute/IP, 429 + Retry-After.
func limitAuth(l *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, 429, "too many attempts, retry in a minute")
			return
		}
		next(w, r)
	}
}
