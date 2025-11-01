package enumeration

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/redops/redops/internal/mitre"
	"github.com/redops/redops/internal/scope"
)

// HTTPModule fetches page metadata, headers, robots/sitemap. Read-only GETs.
type HTTPModule struct{}

func init() { Register(HTTPModule{}) }

func (HTTPModule) Name() string { return "http" }
func (HTTPModule) Description() string {
	return "Web metadata: title, server, tech, headers, TLS, robots, sitemap (T1594/T1046)"
}

func (HTTPModule) Handles(svc ServiceRef) bool {
	if svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8000 || svc.Port == 8443 {
		return true
	}
	n := strings.ToLower(svc.Name)
	return strings.Contains(n, "http") || strings.Contains(n, "web")
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var generatorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

func (HTTPModule) Enumerate(ctx context.Context, sc *scope.Scope, svc ServiceRef, opts Options) (Result, error) {
	if sc == nil {
		return Result{}, fmt.Errorf("scope required")
	}
	if err := sc.Enforce(svc.HostIP); err != nil {
		return Result{}, err
	}
	if svc.Port <= 0 || svc.Port > 65535 {
		return Result{}, fmt.Errorf("invalid port %d", svc.Port)
	}
	timeout := effectiveTimeout(opts.Timeout)
	scheme := "http"
	if svc.Port == 443 || svc.Port == 8443 {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s:%d", scheme, svc.HostIP, svc.Port)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:       (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // lab metadata only, never send creds
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	var obs []Observation
	add := func(kind, detail string) {
		detail = strings.TrimSpace(detail)
		if detail == "" {
			return
		}
		if len(detail) > 300 {
			detail = detail[:300]
		}
		obs = append(obs, Observation{Kind: kind, Detail: detail, TechniqueID: mitre.MapObservation(kind)})
	}

	// 1. Root page.
	body, hdr, tlsState, status, finalURL := fetchPage(ctx, client, base+"/")
	add("http-status", fmt.Sprintf("%s -> %d", base, status))
	if finalURL != "" && finalURL != base+"/" {
		add("http-redirect", finalURL)
	}
	if server := hdr.Get("Server"); server != "" {
		add("http-server", server)
	}
	if powered := hdr.Get("X-Powered-By"); powered != "" {
		add("http-tech", "powered-by: "+powered)
	}
	if m := titleRe.FindStringSubmatch(body); len(m) == 2 {
		t := strings.Join(strings.Fields(m[1]), " ")
		add("http-title", t)
	}
	if m := generatorRe.FindStringSubmatch(body); len(m) == 2 {
		add("http-tech", "generator: "+strings.TrimSpace(m[1]))
	}
	checkSecurityHeaders(hdr, &obs)
	if tlsState != nil {
		add("http-tls", fmt.Sprintf("%s %s", tls.VersionName(tlsState.Version), tls.CipherSuiteName(tlsState.CipherSuite)))
	}

	// 2. robots.txt and sitemap.xml (T1594).
	for _, p := range []string{"/robots.txt", "/sitemap.xml"} {
		b, _, _, code, _ := fetchPage(ctx, client, base+p)
		if code == 200 && len(strings.TrimSpace(b)) > 0 {
			kind := "http-robots"
			if strings.Contains(p, "sitemap") {
				kind = "http-sitemap"
			}
			first := strings.SplitN(strings.TrimSpace(b), "\n", 2)[0]
			add(kind, fmt.Sprintf("%s present (%d bytes): %s", p, len(b), first))
		}
	}

	if len(obs) == 0 {
		return Result{Module: "http", Observations: obs, Summary: "no HTTP response"}, nil
	}
	return Result{Module: "http", Observations: obs, Summary: fmt.Sprintf("%d observations on %s", len(obs), base)}, nil
}

func fetchPage(ctx context.Context, client *http.Client, url string) (body string, hdr http.Header, tlsState *tls.ConnectionState, status int, finalURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", nil, nil, 0, ""
	}
	req.Header.Set("User-Agent", "RedOps-lab/1.0 (authorized assessment)")
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, nil, 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if resp.TLS != nil {
		st := *resp.TLS
		tlsState = &st
	}
	return string(b), resp.Header, tlsState, resp.StatusCode, resp.Request.URL.String()
}

func checkSecurityHeaders(hdr http.Header, obs *[]Observation) {
	for _, h := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if hdr.Get(h) == "" {
			*obs = append(*obs, Observation{Kind: "http-missing-header", Detail: "missing " + h, TechniqueID: mitre.MapObservation("http-missing-header")})
		}
	}
}
