package recon

import (
	"bytes"
	"encoding/json"
	"strings"
)

func splitLines(b []byte) [][]byte {
	var out [][]byte
	for _, l := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(l)) > 0 {
			out = append(out, l)
		}
	}
	return out
}

func extractJSONHost(line []byte) string {
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		// Fall back to bare-line output (subfinder -silent without -json).
		s := strings.TrimSpace(string(line))
		if strings.Contains(s, " ") || strings.Contains(s, "{") {
			return ""
		}
		return s
	}
	if h, ok := m["host"].(string); ok {
		return strings.TrimSpace(h)
	}
	return ""
}
