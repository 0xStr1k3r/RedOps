package validation

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/redops/redops/internal/scope"
)

// splitTarget parses "host:port" (port defaults to 80).
func splitTarget(target string) (host string, port string, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", fmt.Errorf("empty target")
	}
	if i := strings.LastIndex(target, ":"); i >= 0 {
		host, port = strings.TrimSpace(target[:i]), strings.TrimSpace(target[i+1:])
	} else {
		host, port = target, "80"
	}
	if _, _, err := scope.Classify(host); err != nil {
		return "", "", fmt.Errorf("invalid host %q", host)
	}
	if scope.IsBlockedHost(host) {
		return "", "", fmt.Errorf("refusing blocked host %q (cloud metadata guard)", host)
	}
	if port == "" {
		port = "80"
	}
	return host, port, nil
}

// httpClient builds a short-timeout client. TLS unverified: lab metadata
// only, and validators never transmit credentials.
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- read-only lab checks; no credentials ever sent.
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func fetchURL(ctx context.Context, url string) (int, http.Header, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", "RedOps-lab/1.0 (authorized assessment)")
	req.Close = true
	resp, err := httpClient().Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return resp.StatusCode, resp.Header, string(b), nil
}

func schemeFor(port string) string {
	if port == "443" || port == "8443" {
		return "https"
	}
	return "http"
}

// HeadersValidator re-checks a missing security header finding.
type HeadersValidator struct{}

func init() { Register(HeadersValidator{}) }

func (HeadersValidator) Name() string { return "http-security-headers" }
func (HeadersValidator) Description() string {
	return "Re-fetch page, confirm header still missing (read-only GET)"
}

func (HeadersValidator) Matches(title string) bool {
	t := strings.ToLower(title)
	return strings.Contains(t, "missing") && strings.Contains(t, "header")
}

func (HeadersValidator) Run(ctx context.Context, sc *scope.Scope, target string, opts Options) (Result, error) {
	host, port, err := splitTarget(target)
	if err != nil {
		return Result{}, err
	}
	if err := sc.Enforce(host); err != nil {
		return Result{}, err
	}
	_ = opts
	url := fmt.Sprintf("%s://%s:%s/", schemeFor(port), host, port)
	code, hdr, _, err := fetchURL(ctx, url)
	if err != nil {
		return Result{}, fmt.Errorf("fetch: %w", err)
	}
	if code < 200 || code >= 500 {
		return Result{}, fmt.Errorf("unexpected status %d", code)
	}
	// The finding evidence names the header ("missing X"); extract it when possible.
	missing := []string{}
	for _, h := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if hdr.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 {
		return Result{Validator: "http-security-headers", Confirmed: false, Detail: "all checked headers now present; finding may be resolved"}, nil
	}
	return Result{Validator: "http-security-headers", Confirmed: true, Detail: fmt.Sprintf("still missing on %s: %s", url, strings.Join(missing, ", "))}, nil
}

// RobotsValidator re-checks an exposed robots.txt finding.
type RobotsValidator struct{}

func init() { Register(RobotsValidator{}) }

func (RobotsValidator) Name() string { return "http-robots" }
func (RobotsValidator) Description() string {
	return "Re-fetch robots.txt, confirm still reachable (read-only GET)"
}

func (RobotsValidator) Matches(title string) bool {
	return strings.Contains(strings.ToLower(title), "robots.txt")
}

func (RobotsValidator) Run(ctx context.Context, sc *scope.Scope, target string, opts Options) (Result, error) {
	host, port, err := splitTarget(target)
	if err != nil {
		return Result{}, err
	}
	if err := sc.Enforce(host); err != nil {
		return Result{}, err
	}
	_ = opts
	url := fmt.Sprintf("%s://%s:%s/robots.txt", schemeFor(port), host, port)
	code, _, body, err := fetchURL(ctx, url)
	if err != nil {
		return Result{}, fmt.Errorf("fetch: %w", err)
	}
	if code == 200 && len(strings.TrimSpace(body)) > 0 {
		first := strings.SplitN(strings.TrimSpace(body), "\n", 2)[0]
		return Result{Validator: "http-robots", Confirmed: true, Detail: fmt.Sprintf("robots.txt still reachable (%d bytes): %s", len(body), first)}, nil
	}
	return Result{Validator: "http-robots", Confirmed: false, Detail: fmt.Sprintf("robots.txt now returns %d; finding may be resolved", code)}, nil
}

// InterfaceValidator re-checks a sensitive-interface finding.
type InterfaceValidator struct{}

func init() { Register(InterfaceValidator{}) }

func (InterfaceValidator) Name() string { return "http-sensitive-interface" }
func (InterfaceValidator) Description() string {
	return "Re-fetch page, confirm sensitive title still served (read-only GET)"
}

func (InterfaceValidator) Matches(title string) bool {
	return strings.Contains(strings.ToLower(title), "sensitive interface")
}

func (InterfaceValidator) Run(ctx context.Context, sc *scope.Scope, target string, opts Options) (Result, error) {
	host, port, err := splitTarget(target)
	if err != nil {
		return Result{}, err
	}
	if err := sc.Enforce(host); err != nil {
		return Result{}, err
	}
	_ = opts
	url := fmt.Sprintf("%s://%s:%s/", schemeFor(port), host, port)
	code, _, body, err := fetchURL(ctx, url)
	if err != nil {
		return Result{}, fmt.Errorf("fetch: %w", err)
	}
	if code == 200 && looksSensitive(body) {
		return Result{Validator: "http-sensitive-interface", Confirmed: true, Detail: fmt.Sprintf("%s still serves a sensitive-titled page (HTTP %d); exposure confirmed, auth posture needs manual review", url, code)}, nil
	}
	return Result{Validator: "http-sensitive-interface", Confirmed: false, Detail: fmt.Sprintf("%s now returns %d without sensitive markers", url, code)}, nil
}

func looksSensitive(body string) bool {
	t := strings.ToLower(body)
	for _, k := range []string{"admin", "login", "dashboard", "console", "password"} {
		if strings.Contains(t, k) {
			return true
		}
	}
	return false
}

// VersionValidator re-checks a server version disclosure finding.
type VersionValidator struct{}

func init() { Register(VersionValidator{}) }

func (VersionValidator) Name() string { return "http-version-disclosure" }
func (VersionValidator) Description() string {
	return "Re-fetch page, confirm version banner still disclosed (read-only GET)"
}

func (VersionValidator) Matches(title string) bool {
	return strings.Contains(strings.ToLower(title), "version disclosure")
}

func (VersionValidator) Run(ctx context.Context, sc *scope.Scope, target string, opts Options) (Result, error) {
	host, port, err := splitTarget(target)
	if err != nil {
		return Result{}, err
	}
	if err := sc.Enforce(host); err != nil {
		return Result{}, err
	}
	_ = opts
	url := fmt.Sprintf("%s://%s:%s/", schemeFor(port), host, port)
	code, hdr, _, err := fetchURL(ctx, url)
	if err != nil {
		return Result{}, fmt.Errorf("fetch: %w", err)
	}
	if server := hdr.Get("Server"); strings.Contains(server, "/") {
		return Result{Validator: "http-version-disclosure", Confirmed: true, Detail: fmt.Sprintf("%s still discloses %q (HTTP %d)", url, server, code)}, nil
	}
	return Result{Validator: "http-version-disclosure", Confirmed: false, Detail: "Server header no longer carries a version"}, nil
}
