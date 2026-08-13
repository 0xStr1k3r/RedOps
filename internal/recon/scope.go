package recon

import (
	"github.com/0xStr1k3r/RedOps/internal/scope"
)

func classifyTarget(t string) (scope.EntryType, string, error) {
	return scope.Classify(t)
}
