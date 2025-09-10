package recon

import (
	"github.com/redops/redops/internal/scope"
)

func classifyTarget(t string) (scope.EntryType, string, error) {
	return scope.Classify(t)
}
