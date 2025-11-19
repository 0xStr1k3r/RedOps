package attack

// Confidence states. The engine emits only observed/potential; validated and
// confirmed require operator verification (Phase 8) or manual confirmation.
const (
	ConfObserved  = "observed"
	ConfPotential = "potential"
	ConfValidated = "validated"
	ConfConfirmed = "confirmed"
)

// PathNode is one step: a reference into the attack graph.
type PathNode struct {
	Kind  string `json:"kind"`  // Target | Host | Service | Finding | Technique
	ID    string `json:"id"`    // graph node id
	Label string `json:"label"` // human-readable step
}

// Path is one attacker-to-objective chain with scoring.
type Path struct {
	ID                 string     `json:"id"`
	ProjectID          string     `json:"project_id"`
	Nodes              []PathNode `json:"nodes"`
	Length             int        `json:"length"`
	Risk               int        `json:"risk"`
	Confidence         string     `json:"confidence"`
	Techniques         []string   `json:"techniques"`
	RequiredPrivileges []string   `json:"required_privileges"`
	Objective          string     `json:"objective"`
}

// severityBase maps terminal finding severity to base risk.
func severityBase(sev string) int {
	switch sev {
	case "critical":
		return 100
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	default:
		return 10
	}
}

// Score computes risk 0-100: severity base +5 per technique (cap +15),
// -2 per hop beyond 4. Deterministic and documented in docs/attackpaths.md.
func Score(severity string, techCount, hops int) int {
	risk := severityBase(severity)
	if techCount > 3 {
		techCount = 3
	}
	risk += 5 * techCount
	if hops > 4 {
		risk -= 2 * (hops - 4)
	}
	if risk < 0 {
		return 0
	}
	if risk > 100 {
		return 100
	}
	return risk
}
