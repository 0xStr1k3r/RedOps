package validation

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redops/redops/internal/scope"
)

// TLSValidator re-checks a weak-TLS finding with a handshake only.
// No data is exchanged beyond the handshake; nothing is exploited.
type TLSValidator struct{}

func init() { Register(TLSValidator{}) }

func (TLSValidator) Name() string { return "tls-version" }
func (TLSValidator) Description() string {
	return "TLS handshake only, confirm weak version still negotiated"
}

func (TLSValidator) Matches(title string) bool {
	return strings.Contains(strings.ToLower(title), "weak tls")
}

func (TLSValidator) Run(ctx context.Context, sc *scope.Scope, target string, opts Options) (Result, error) {
	host, port, err := splitTarget(target)
	if err != nil {
		return Result{}, err
	}
	if err := sc.Enforce(host); err != nil {
		return Result{}, err
	}
	if port == "80" {
		port = "443" // weak-TLS findings imply a TLS endpoint
	}
	timeout := effectiveTimeout(opts.Timeout)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return Result{}, fmt.Errorf("handshake: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	st := conn.ConnectionState()
	version := tls.VersionName(st.Version)
	if isWeak(version) {
		return Result{Validator: "tls-version", Confirmed: true, Detail: fmt.Sprintf("%s:%s still negotiates %s (%s)", host, port, version, tls.CipherSuiteName(st.CipherSuite))}, nil
	}
	_ = ctx
	return Result{Validator: "tls-version", Confirmed: false, Detail: fmt.Sprintf("%s:%s now negotiates %s; finding may be resolved", host, port, version)}, nil
}

func isWeak(version string) bool {
	v := strings.ToLower(version)
	return strings.Contains(v, "1.0") || strings.Contains(v, "1.1") || strings.Contains(v, "ssl")
}

// SSHValidator re-checks a deprecated-SSH finding with a banner read only.
type SSHValidator struct{}

func init() { Register(SSHValidator{}) }

func (SSHValidator) Name() string        { return "ssh-version" }
func (SSHValidator) Description() string { return "Banner read only, confirm SSHv1 still offered" }

func (SSHValidator) Matches(title string) bool {
	t := strings.ToLower(title)
	return strings.Contains(t, "sshv1") || strings.Contains(t, "ssh1")
}

func (SSHValidator) Run(ctx context.Context, sc *scope.Scope, target string, opts Options) (Result, error) {
	host, port, err := splitTarget(target)
	if err != nil {
		return Result{}, err
	}
	if err := sc.Enforce(host); err != nil {
		return Result{}, err
	}
	if port == "80" {
		port = "22"
	}
	timeout := effectiveTimeout(opts.Timeout)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return Result{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return Result{}, fmt.Errorf("banner read: %w", err)
	}
	banner := strings.TrimSpace(line)
	if strings.HasPrefix(banner, "SSH-1.") {
		return Result{Validator: "ssh-version", Confirmed: true, Detail: "still offers " + banner}, nil
	}
	return Result{Validator: "ssh-version", Confirmed: false, Detail: "now offers " + banner}, nil
}
