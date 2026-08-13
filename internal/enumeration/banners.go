package enumeration

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/0xStr1k3r/RedOps/internal/mitre"
	"github.com/0xStr1k3r/RedOps/internal/scope"
)

// SSHBannerModule grabs the SSH version banner only. No auth attempts.
type SSHBannerModule struct{}

func init() { Register(SSHBannerModule{}) }

func (SSHBannerModule) Name() string        { return "ssh-banner" }
func (SSHBannerModule) Description() string { return "SSH banner grab, no auth (T1592)" }

func (SSHBannerModule) Handles(svc ServiceRef) bool {
	if svc.Port == 22 {
		return true
	}
	return strings.Contains(strings.ToLower(svc.Name), "ssh")
}

func (SSHBannerModule) Enumerate(ctx context.Context, sc *scope.Scope, svc ServiceRef, opts Options) (Result, error) {
	if sc == nil {
		return Result{}, fmt.Errorf("scope required")
	}
	if err := sc.Enforce(svc.HostIP); err != nil {
		return Result{}, err
	}
	timeout := effectiveTimeout(opts.Timeout)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", svc.HostIP, svc.Port))
	if err != nil {
		return Result{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return Result{}, fmt.Errorf("banner read: %w", err)
	}
	banner := strings.TrimSpace(line)
	if !strings.HasPrefix(banner, "SSH-") {
		return Result{}, fmt.Errorf("not an SSH banner: %q", trunc(banner, 80))
	}
	return Result{
		Module: "ssh-banner",
		Observations: []Observation{
			{Kind: "ssh-banner", Detail: banner, TechniqueID: mitre.MapObservation("service-banner")},
		},
		Summary: "SSH banner: " + banner,
	}, nil
}

// TCPBannerModule is the generic fallback: connect + read up to 1 line/1KB.
// Handles anything the specific modules decline (ftp echoes, smtp, pop3...).
type TCPBannerModule struct{}

func init() { Register(TCPBannerModule{}) }

func (TCPBannerModule) Name() string        { return "tcp-banner" }
func (TCPBannerModule) Description() string { return "Generic TCP banner fallback (T1046)" }

func (TCPBannerModule) Handles(svc ServiceRef) bool {
	return svc.Port > 0 && svc.Port <= 65535
}

func (TCPBannerModule) Enumerate(ctx context.Context, sc *scope.Scope, svc ServiceRef, opts Options) (Result, error) {
	if sc == nil {
		return Result{}, fmt.Errorf("scope required")
	}
	if err := sc.Enforce(svc.HostIP); err != nil {
		return Result{}, err
	}
	timeout := effectiveTimeout(opts.Timeout)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", svc.HostIP, svc.Port))
	if err != nil {
		return Result{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return Result{Module: "tcp-banner", Summary: "port open, no banner"}, nil
	}
	banner := strings.TrimSpace(string(buf[:n]))
	return Result{
		Module: "tcp-banner",
		Observations: []Observation{
			{Kind: "service-banner", Detail: trunc(banner, 200), TechniqueID: mitre.MapObservation("service-banner")},
		},
		Summary: "banner: " + trunc(banner, 120),
	}, nil
}

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n]
	}
	return s
}
