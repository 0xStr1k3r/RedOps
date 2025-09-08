// Package httpx parses httpx JSONL output into host/service observations.
// Execution lives in internal/recon (scope-gated); this package never runs commands.
package httpx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Result is one probed URL.
type Result struct {
	Input      string   `json:"input"`
	URL        string   `json:"url"`
	Scheme     string   `json:"scheme"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Server     string   `json:"webserver"`
	Tech       []string `json:"tech"`
	TLS        bool     `json:"tls"`
}

// ParseJSONL parses `httpx -json` line-delimited output. Skips blank/invalid lines.
func ParseJSONL(data []byte) ([]Result, error) {
	var out []Result
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var r Result
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("httpx line %d: %w", line, err)
		}
		if r.Port == 0 {
			r.Port = portFromURL(r.URL, r.Scheme)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func portFromURL(u, scheme string) int {
	// Best-effort: look for explicit :port, else scheme default.
	if i := strings.LastIndex(u, ":"); i > 0 {
		rest := u[i+1:]
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end > 0 {
			if p, err := strconv.Atoi(rest[:end]); err == nil {
				return p
			}
		}
	}
	if scheme == "https" {
		return 443
	}
	return 80
}
