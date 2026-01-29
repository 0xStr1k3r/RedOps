package enumeration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redops/redops/internal/project"
	"github.com/redops/redops/internal/scope"
)

func testScope(t *testing.T, entries ...string) *scope.Scope {
	t.Helper()
	s, err := scope.ParseEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testStore(t *testing.T) *project.Store {
	t.Helper()
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestMatch(t *testing.T) {
	if got := Match(ServiceRef{HostIP: "10.0.0.1", Port: 80}); got != "http" {
		t.Fatalf("port 80 -> %q", got)
	}
	if got := Match(ServiceRef{HostIP: "10.0.0.1", Port: 22}); got != "ssh-banner" {
		t.Fatalf("port 22 -> %q", got)
	}
	if got := Match(ServiceRef{HostIP: "10.0.0.1", Port: 9999}); got != "tcp-banner" {
		t.Fatalf("unknown port -> %q", got)
	}
}

func TestHTTPModule(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24")
		w.Header().Set("X-Powered-By", "PHP/8.1")
		fmt.Fprint(w, `<html><head><title>Lab Console</title><meta name="generator" content="WordPress 6.4"></head></html>`)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin\n")
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	// srv.URL like http://127.0.0.1:PORT — in scope for the test.
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	sc := testScope(t, "127.0.0.0/8")
	mod, _ := Get("http")
	res, err := mod.Enumerate(context.Background(), sc, ServiceRef{HostIP: host, Port: port}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, o := range res.Observations {
		joined += o.Kind + "=" + o.Detail + "\n"
	}
	for _, want := range []string{"http-title=Lab Console", "http-server=nginx", "http-robots", "http-missing-header=missing Content-Security-Policy"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestHTTPNonHTTPServiceFails(t *testing.T) {
	// An SSH banner on the port: forcing the http module must fail loudly,
	// never emit "missing header" findings for a non-HTTP service.
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
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	sc := testScope(t, "127.0.0.0/8")
	mod, _ := Get("http")
	if _, err := mod.Enumerate(context.Background(), sc, ServiceRef{HostIP: host, Port: port}, Options{}); err == nil {
		t.Fatal("http module on SSH port must fail, not invent findings")
	}
}

func TestHTTPOutOfScope(t *testing.T) {
	sc := testScope(t, "10.10.10.0/24")
	mod, _ := Get("http")
	if _, err := mod.Enumerate(context.Background(), sc, ServiceRef{HostIP: "8.8.8.8", Port: 80}, Options{}); err == nil {
		t.Fatal("out-of-scope must fail before any connection")
	}
}

func TestSSHBanner(t *testing.T) {
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
	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	sc := testScope(t, "127.0.0.0/8")
	mod, _ := Get("ssh-banner")
	res, err := mod.Enumerate(context.Background(), sc, ServiceRef{HostIP: host, Port: port}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Observations) != 1 || !strings.Contains(res.Observations[0].Detail, "OpenSSH") {
		t.Fatalf("unexpected %+v", res)
	}
}

func TestEnqueueGate(t *testing.T) {
	st := testStore(t)
	p, _ := st.CreateProject("acme", "")
	if _, err := Enqueue(context.Background(), st, p.ID, "10.10.10.10", 80, "", "alice"); err == nil {
		t.Fatal("no scope must fail")
	}
	_, _ = st.AddScopeEntry(p.ID, "10.10.10.0/24")
	j, err := Enqueue(context.Background(), st, p.ID, "10.10.10.10", 80, "", "alice")
	if err != nil || j.Module != "http" {
		t.Fatalf("auto-match http failed: %v %+v", err, j)
	}
	if _, err := Enqueue(context.Background(), st, p.ID, "8.8.8.8", 80, "", "alice"); err == nil {
		t.Fatal("out-of-scope must fail")
	}
	if _, err := Enqueue(context.Background(), st, p.ID, "10.10.10.10", 99999, "", "alice"); err == nil {
		t.Fatal("bad port must fail")
	}
}
