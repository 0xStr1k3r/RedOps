package nmap

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// Host and Service mirror the subset of Nmap XML RedOps stores.
type Host struct {
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname,omitempty"`
	State    string    `json:"state,omitempty"`
	OS       string    `json:"os,omitempty"`
	Services []Service `json:"services"`
}

// Service is one open/filtered port.
type Service struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Name     string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    struct{ State string `xml:"state,attr"` } `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []nmapPort `xml:"ports>port"`
	OS    struct {
		Matches []struct {
			Name string `xml:"name,attr"`
		} `xml:"osmatch"`
	} `xml:"os"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct{ State string `xml:"state,attr"` } `xml:"state"`
	Service  struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
}

// ParseXML parses `nmap -oX -` output. No command execution here:
// execution adapters live in internal/recon (Phase 2) behind scope enforcement.
func ParseXML(data []byte) ([]Host, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}
	var out []Host
	for _, h := range run.Hosts {
		host := Host{State: h.Status.State}
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				host.IP = a.Addr
				break
			}
		}
		if host.IP == "" && len(h.Addresses) > 0 {
			host.IP = h.Addresses[0].Addr
		}
		if len(h.Hostnames) > 0 {
			host.Hostname = h.Hostnames[0].Name
		}
		if len(h.OS.Matches) > 0 {
			host.OS = h.OS.Matches[0].Name
		}
		for _, p := range h.Ports {
			// Store open + filtered; skip closed to keep findings signal-rich.
			if p.State.State == "closed" {
				continue
			}
			out_svc := Service{
				Port:     p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
				Name:     strings.TrimSpace(p.Service.Name),
				Product:  strings.TrimSpace(p.Service.Product),
				Version:  strings.TrimSpace(p.Service.Version),
			}
			host.Services = append(host.Services, out_svc)
		}
		if host.IP != "" {
			out = append(out, host)
		}
	}
	return out, nil
}
