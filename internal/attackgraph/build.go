package attackgraph

import (
	"fmt"
	"strings"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

// Build derives the assessment graph from stored data:
// Project -HAS_TARGET-> Target -MATCHES-> Host -RUNS-> Service -HAS_FINDING->
// Finding -MAPS_TO-> Technique. Findings whose target matches no known
// service attach to their host, else to the project, so nothing is orphaned.
func Build(st *project.Store, projectID string) (*Graph, error) {
	p, err := st.GetProject(projectID)
	if err != nil {
		return nil, err
	}
	g := &Graph{}
	addNode := func(n Node) string {
		if n.Props == nil {
			n.Props = map[string]string{}
		}
		g.Nodes = append(g.Nodes, n)
		return n.ID
	}
	addEdge := func(from, to, typ, reason string) {
		g.Edges = append(g.Edges, Edge{From: from, To: to, Type: typ, Reason: reason})
	}

	pid := "project:" + p.ID
	addNode(Node{ID: pid, Kind: KindProject, Labels: []string{"Project"},
		Props: map[string]string{"name": p.Name, "id": p.ID}})

	targets, err := st.ListTargets(projectID)
	if err != nil {
		return nil, err
	}
	for _, t := range targets {
		tid := "target:" + t.Value
		addNode(Node{ID: tid, Kind: KindTarget, Labels: []string{"Target"},
			Props: map[string]string{"value": t.Value, "type": t.Type}})
		addEdge(pid, tid, EdgeHasTarget, fmt.Sprintf("target %s in scope, added by %s", t.Value, nonEmpty(t.AddedBy, "operator")))
	}

	hosts, err := st.ListHosts(projectID)
	if err != nil {
		return nil, err
	}
	hostIDs := map[string]string{}
	for _, h := range hosts {
		hid := "host:" + h.IP
		hostIDs[h.IP] = hid
		addNode(Node{ID: hid, Kind: KindHost, Labels: []string{"Host"},
			Props: map[string]string{"ip": h.IP, "hostname": h.Hostname, "os": h.OS, "source": h.Source}})
		addEdge(pid, hid, EdgeHasHost, fmt.Sprintf("host discovered by %s", nonEmpty(h.Source, "recon")))
		if _, ok := targetID(targets, h.IP); ok {
			addEdge("target:"+h.IP, hid, EdgeMatches, "scope target observed as live host")
		}
	}

	services, err := st.ListServices(projectID)
	if err != nil {
		return nil, err
	}
	svcIDs := map[string]string{} // "ip:port/proto" -> node id
	for _, s := range services {
		key := fmt.Sprintf("%s:%d/%s", s.HostIP, s.Port, proto(s.Protocol))
		sid := "svc:" + key
		svcIDs[key] = sid
		desc := fmt.Sprintf("%s %s", s.Product, s.Version)
		desc = strings.TrimSpace(desc)
		if desc == "" {
			desc = s.Name
		}
		addNode(Node{ID: sid, Kind: KindService, Labels: []string{"Service"},
			Props: map[string]string{
				"host": s.HostIP, "port": fmt.Sprint(s.Port), "protocol": proto(s.Protocol),
				"state": s.State, "name": s.Name, "product": s.Product, "version": s.Version,
			}})
		if hid, ok := hostIDs[s.HostIP]; ok {
			reason := "port observed open"
			if desc != "" {
				reason = fmt.Sprintf("port observed open (%s)", trunc(desc, 80))
			}
			addEdge(hid, sid, EdgeRuns, reason)
		} else {
			addEdge(pid, sid, EdgeRuns, "service on unknown host")
		}
	}

	findings, err := st.ListFindings(projectID, project.FindingFilter{})
	if err != nil {
		return nil, err
	}
	techSeen := map[string]bool{}
	for _, f := range findings {
		fid := "finding:" + f.ID
		addNode(Node{ID: fid, Kind: KindFinding, Labels: []string{"Finding"},
			Props: map[string]string{"title": f.Title, "severity": f.Severity, "target": f.Target, "source": f.Source}})
		// Attach to service when target is host:port, else host, else project.
		if sid, ok := svcIDs[svcKey(f.Target)]; ok {
			addEdge(sid, fid, EdgeHasFinding, fmt.Sprintf("rule %s raised [%s] finding", nonEmpty(f.Source, "engine"), f.Severity))
		} else if hid, ok := hostIDs[hostOf(f.Target)]; ok {
			addEdge(hid, fid, EdgeHasFinding, fmt.Sprintf("host-level [%s] finding", f.Severity))
		} else {
			addEdge(pid, fid, EdgeHasFinding, fmt.Sprintf("project-level [%s] finding", f.Severity))
		}
		if f.TechniqueID != "" && !techSeen[f.TechniqueID] {
			techSeen[f.TechniqueID] = true
			addNode(Node{ID: "technique:" + f.TechniqueID, Kind: KindTechnique, Labels: []string{"Technique"},
				Props: map[string]string{"technique_id": f.TechniqueID}})
		}
		if f.TechniqueID != "" {
			addEdge(fid, "technique:"+f.TechniqueID, EdgeMapsTo, "rule catalog maps observation to "+f.TechniqueID)
		}
	}
	return g, nil
}

func targetID(targets []project.Target, ip string) (string, bool) {
	for _, t := range targets {
		if t.Value == ip {
			return t.Value, true
		}
	}
	return "", false
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func proto(p string) string {
	if p == "" {
		return "tcp"
	}
	return strings.ToLower(p)
}

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n]
	}
	return s
}

// svcKey normalizes "10.0.0.1:80" to "10.0.0.1:80/tcp" for service lookup.
func svcKey(target string) string {
	host, port := splitHostPort(target)
	if port == "" {
		return ""
	}
	return host + ":" + port + "/tcp"
}

// hostOf returns the host part of "host:port" or the whole value.
func hostOf(target string) string {
	h, _ := splitHostPort(target)
	return h
}

func splitHostPort(target string) (string, string) {
	i := strings.LastIndex(target, ":")
	if i < 0 {
		return strings.TrimSpace(target), ""
	}
	return strings.TrimSpace(target[:i]), strings.TrimSpace(target[i+1:])
}
