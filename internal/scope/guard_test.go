package scope

import "testing"

func TestBlockedHosts(t *testing.T) {
	for _, h := range []string{"169.254.169.254", "100.100.100.100", "metadata.google.internal", "METADATA.GOOGLE.INTERNAL", "instance-data", "user@evil.com"} {
		if !IsBlockedHost(h) {
			t.Errorf("must block %q", h)
		}
	}
	for _, h := range []string{"10.10.10.10", "example.com", "web01.lab", "127.0.0.1"} {
		if IsBlockedHost(h) {
			t.Errorf("must not block lab host %q", h)
		}
	}
}
