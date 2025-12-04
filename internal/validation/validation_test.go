package validation

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redops/redops/internal/project"
	"github.com/redops/redops/internal/scope"
)

func testScope(t *testing.T) *scope.Scope {
	t.Helper()
	s, err := scope.ParseEntries([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24")
		fmt.Fprint(w, `<html><head><title>Admin Console</title></head></html>`)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin\n")
	})
	return httptest.NewServer(mux)
}

func hostPort(t *testing.T, url string) string {
	t.Helper()
	u := strings.TrimPrefix(url, "https://")
	u = strings.TrimPrefix(u, "http://")
	hp, _, _ := strings.Cut(u, "/")
	return hp
}

func TestHeaderValidatorConfirms(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	v, _ := Get("http-security-headers")
	res, err := v.Run(context.Background(), testScope(t), hostPort(t, srv.URL), Options{})
	if err != nil || !res.Confirmed {
		t.Fatalf("expected confirm, got %+v %v", res, err)
	}
	if !strings.Contains(res.Detail, "Content-Security-Policy") {
		t.Fatalf("detail: %s", res.Detail)
	}
}

func TestRobotsValidator(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	v, _ := Get("http-robots")
	res, err := v.Run(context.Background(), testScope(t), hostPort(t, srv.URL), Options{})
	if err != nil || !res.Confirmed {
		t.Fatalf("expected confirm, got %+v %v", res, err)
	}
}

func TestInterfaceValidator(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	v, _ := Get("http-sensitive-interface")
	res, err := v.Run(context.Background(), testScope(t), hostPort(t, srv.URL), Options{})
	if err != nil || !res.Confirmed {
		t.Fatalf("expected confirm, got %+v %v", res, err)
	}
}

func TestVersionValidatorNegative(t *testing.T) {
	// Server without version token: must NOT confirm.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	v, _ := Get("http-version-disclosure")
	res, err := v.Run(context.Background(), testScope(t), hostPort(t, srv.URL), Options{})
	if err != nil || res.Confirmed {
		t.Fatalf("must not confirm versionless banner: %+v %v", res, err)
	}
}

func TestOutOfScopeBlocked(t *testing.T) {
	v, _ := Get("http-robots")
	sc, _ := scope.ParseEntries([]string{"10.10.10.0/24"})
	if _, err := v.Run(context.Background(), sc, "8.8.8.8:80", Options{}); err == nil {
		t.Fatal("out-of-scope must fail before connecting")
	}
}

func TestTLSValidatorWeakAndStrong(t *testing.T) {
	weak := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	weak.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10}
	weak.StartTLS()
	defer weak.Close()
	v, _ := Get("tls-version")
	res, err := v.Run(context.Background(), testScope(t), hostPort(t, weak.URL), Options{})
	if err != nil {
		t.Skipf("TLS1.0 handshake unsupported here: %v", err)
	}
	if !res.Confirmed {
		t.Fatalf("weak TLS must confirm: %+v", res)
	}

	strong := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer strong.Close()
	res, err = v.Run(context.Background(), testScope(t), hostPort(t, strong.URL), Options{})
	if err != nil || res.Confirmed {
		t.Fatalf("strong TLS must not confirm: %+v %v", res, err)
	}
}

func TestSSHValidator(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprint(c, "SSH-2.0-OpenSSH_9.6\r\n")
			c.Close()
		}
	}()
	v, _ := Get("ssh-version")
	res, err := v.Run(context.Background(), testScope(t), ln.Addr().String(), Options{})
	if err != nil || res.Confirmed {
		t.Fatalf("SSH-2.0 must not confirm SSHv1: %+v %v", res, err)
	}
}

func TestValidateFindingPromotes(t *testing.T) {
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.CreateProject("acme", "")
	_, _ = st.AddScopeEntry(p.ID, "127.0.0.0/8")
	srv := testServer()
	defer srv.Close()
	hostport := hostPort(t, srv.URL)
	host, _, _ := net.SplitHostPort(hostport)
	_ = host
	ok, err := st.CreateFinding(p.ID, project.FindingRow{Title: "Exposed robots.txt", Severity: "info", Target: hostport, TechniqueID: "T1594"}, "k1")
	if err != nil || !ok {
		t.Fatal(err)
	}
	rows, _ := st.ListFindings(p.ID, project.FindingFilter{})
	results, promoted, err := ValidateFinding(context.Background(), st, p.ID, rows[0].ID, "alice", Options{})
	if err != nil || !promoted || len(results) != 1 || !results[0].Confirmed {
		t.Fatalf("results=%+v promoted=%v err=%v", results, promoted, err)
	}
	after, _ := st.GetFinding(p.ID, rows[0].ID)
	if after.Confidence != "validated" {
		t.Fatalf("confidence: %s", after.Confidence)
	}
	runs, _ := st.ListValidationRuns(p.ID, rows[0].ID)
	if len(runs) != 1 || !runs[0].Success {
		t.Fatalf("runs: %+v", runs)
	}
}

func TestNoValidatorMatch(t *testing.T) {
	st, _ := project.Open(":memory:")
	defer st.Close()
	p, _ := st.CreateProject("acme", "")
	_, _ = st.AddScopeEntry(p.ID, "127.0.0.0/8")
	st.CreateFinding(p.ID, project.FindingRow{Title: "Something exotic", Severity: "info", Target: "127.0.0.1:9"}, "k9")
	rows, _ := st.ListFindings(p.ID, project.FindingFilter{})
	if _, _, err := ValidateFinding(context.Background(), st, p.ID, rows[0].ID, "alice", Options{}); err == nil {
		t.Fatal("unmatched finding must error clearly")
	}
}
