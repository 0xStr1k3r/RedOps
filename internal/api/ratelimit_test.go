package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(3, time.Minute)
	ok := 0
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/x", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()
		limitAuth(l, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })(rr, req)
		if rr.Code == 200 {
			ok++
		} else if rr.Code != 429 {
			t.Fatalf("unexpected code %d", rr.Code)
		}
	}
	if ok != 3 {
		t.Fatalf("expected 3 allowed then 429s, got %d allowed", ok)
	}
	// Other IPs unaffected.
	req := httptest.NewRequest("POST", "/x", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rr := httptest.NewRecorder()
	limitAuth(l, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })(rr, req)
	if rr.Code != 200 {
		t.Fatal("per-IP bucket leaked across clients")
	}
}

func TestAuthRateLimitedEndToEnd(t *testing.T) {
	h, _ := testRouter(t)
	for i := 0; i < 11; i++ {
		rr := doReq(h, "POST", "/api/v1/auth/login", "", `{"username":"nobody","password":"wrongpassword"}`)
		if i < 10 && rr.Code != 401 {
			t.Fatalf("attempt %d: expected 401, got %d", i, rr.Code)
		}
		if i == 10 && rr.Code != 429 {
			t.Fatalf("attempt 11 must be 429, got %d", rr.Code)
		}
	}
}
