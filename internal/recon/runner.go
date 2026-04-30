package recon

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/redops/redops/internal/scope"
)

var portsRe = regexp.MustCompile(`^[0-9,\- ]{1,100}$`)

// ValidateOptions rejects anything outside the allowlist.
func ValidateOptions(opts Options) error {
	if opts.Ports != "" {
		if !portsRe.MatchString(opts.Ports) {
			return fmt.Errorf("invalid ports %q: use digits, commas, dashes only", opts.Ports)
		}
		// Reject empty segments like "80,,443".
		for _, seg := range strings.Split(strings.ReplaceAll(opts.Ports, " ", ""), ",") {
			if seg == "" {
				return fmt.Errorf("invalid ports %q", opts.Ports)
			}
		}
	}
	switch opts.Profile {
	case "", "fast", "full", "top100":
		return nil
	default:
		return fmt.Errorf("unknown profile %q (fast|full|top100)", opts.Profile)
	}
}

func effectiveTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 5 * time.Minute
	}
	if d > 30*time.Minute {
		return 30 * time.Minute
	}
	return d
}

// runBinary is the single choke point for process execution:
//   - scope.Enforce(target) first (defense in depth; callers already checked)
//   - LookPath for a clear "install X" error instead of exec failure
//   - exec.CommandContext with timeout, argv only (no shell), stdin closed
//   - output capped at 5 MiB to protect the API/worker
func runBinary(ctx context.Context, sc *scope.Scope, binary, target string, args []string, opts Options) ([]byte, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	if sc == nil {
		return nil, fmt.Errorf("scope required (refusing to run %s without scope)", binary)
	}
	if err := sc.Enforce(target); err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(target), "-") {
		return nil, fmt.Errorf("invalid target %q", target)
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("%s not installed (exec: %q not found in PATH). Install it or use another adapter", binary, binary)
	}
	timeout := effectiveTimeout(opts.Timeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// #nosec G204 -- binary resolved via LookPath from the allowlisted adapter registry; argv only, never a shell.
	cmd := exec.CommandContext(ctx, path, args...)
	// Detach stdin so tools never block reading the terminal.
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	// Cap buffers: 5 MiB each.
	cmd.Stdout = &limitedWriter{W: &stdout, N: 5 << 20}
	cmd.Stderr = &limitedWriter{W: &stderr, N: 1 << 20}
	err = cmd.Run()
	out := stdout.Bytes()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", binary, timeout)
	}
	if err != nil {
		// Tools like nmap return nonzero with partial output; surface stderr briefly.
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%s failed: %v (%s)", binary, err, msg)
		}
		// Partial output is still parseable; let the caller decide.
		return out, nil
	}
	return out, nil
}

type limitedWriter struct {
	W *bytes.Buffer
	N int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	room := l.N - l.W.Len()
	if room <= 0 {
		return len(p), nil // discard overflow
	}
	if len(p) > room {
		p = p[:room]
	}
	return l.W.Write(p)
}
