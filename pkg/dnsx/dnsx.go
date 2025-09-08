// Package dnsx parses dnsx JSONL output into DNS observations.
// Execution lives in internal/recon (scope-gated); this package never runs commands.
package dnsx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
)

// Result is one resolved name.
type Result struct {
	Host  string   `json:"host"`
	A     []string `json:"a"`
	CNAME []string `json:"cname"`
}

// ParseJSONL parses `dnsx -json` line-delimited output.
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
			return nil, fmt.Errorf("dnsx line %d: %w", line, err)
		}
		if r.Host == "" {
			return nil, fmt.Errorf("dnsx line %d: missing host", line)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}
