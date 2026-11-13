// Package drift compares two scan reports and lists what changed.
package drift

import (
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nerdinthenord/protolan/internal/report"
)

// Change kinds.
const (
	HostNew       = "host_new"
	HostGone      = "host_gone"
	PortOpened    = "port_opened"
	PortClosed    = "port_closed"
	ServiceChange = "service_changed"
	CertChange    = "certificate_changed"
	DeviceChange  = "device_changed"
)

// Change is one difference between two scans.
type Change struct {
	Kind    string `json:"kind"`
	Address string `json:"address"`
	Port    uint16 `json:"port,omitempty"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

// Report is the result of a comparison.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	OldStartedAt  time.Time `json:"old_started_at"`
	NewStartedAt  time.Time `json:"new_started_at"`
	// Warnings explain why some changes may be artefacts of how the scans
	// were run rather than of the network.
	Warnings []string `json:"warnings"`
	Changes  []Change `json:"changes"`
}

// Compare lists differences in responsive hosts, open ports, services,
// certificates and device verdicts. A host or port absent from the newer
// scan may simply have been offline.
func Compare(old, cur report.Document) Report {
	r := Report{SchemaVersion: "1", OldStartedAt: old.StartedAt, NewStartedAt: cur.StartedAt,
		Warnings: []string{}, Changes: []Change{}}
	if !slices.Equal(old.Parameters.Targets, cur.Parameters.Targets) || old.Parameters.Ports != cur.Parameters.Ports {
		r.Warnings = append(r.Warnings, "the scans covered different targets or ports; some changes reflect scope, not the network")
	}
	if old.Summary.Interrupted || cur.Summary.Interrupted {
		r.Warnings = append(r.Warnings, "at least one scan was interrupted and is incomplete")
	}
	if old.Parameters.Identify != cur.Parameters.Identify {
		r.Warnings = append(r.Warnings, "only one scan identified services; service and device changes are not compared")
	}
	compareSvc := old.Parameters.Identify && cur.Parameters.Identify

	oldHosts, curHosts := index(old), index(cur)
	for addr, oh := range oldHosts {
		ch, ok := curHosts[addr]
		if !ok {
			r.Changes = append(r.Changes, Change{Kind: HostGone, Address: addr})
			continue
		}
		op, cp := openPorts(oh), openPorts(ch)
		for port, o := range op {
			c, ok := cp[port]
			if !ok {
				r.Changes = append(r.Changes, Change{Kind: PortClosed, Address: addr, Port: port})
				continue
			}
			if !compareSvc {
				continue
			}
			if a, b := svcText(o), svcText(c); a != b {
				r.Changes = append(r.Changes, Change{Kind: ServiceChange, Address: addr, Port: port, Before: a, After: b})
			}
			if a, b := certText(o), certText(c); a != b {
				r.Changes = append(r.Changes, Change{Kind: CertChange, Address: addr, Port: port, Before: a, After: b})
			}
		}
		for port := range cp {
			if _, ok := op[port]; !ok {
				r.Changes = append(r.Changes, Change{Kind: PortOpened, Address: addr, Port: port})
			}
		}
		if a, b := deviceText(oh), deviceText(ch); compareSvc && a != b {
			r.Changes = append(r.Changes, Change{Kind: DeviceChange, Address: addr, Before: a, After: b})
		}
	}
	for addr := range curHosts {
		if _, ok := oldHosts[addr]; !ok {
			r.Changes = append(r.Changes, Change{Kind: HostNew, Address: addr})
		}
	}
	sort.Slice(r.Changes, func(i, j int) bool {
		a, b := r.Changes[i], r.Changes[j]
		if a.Address != b.Address {
			x, _ := netip.ParseAddr(a.Address)
			y, _ := netip.ParseAddr(b.Address)
			return x.Less(y)
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Kind < b.Kind
	})
	return r
}

func index(d report.Document) map[string]report.Host {
	m := make(map[string]report.Host, len(d.Hosts))
	for _, h := range d.Hosts {
		m[h.Address] = h
	}
	return m
}

func openPorts(h report.Host) map[uint16]report.Port {
	m := make(map[uint16]report.Port)
	for _, p := range h.Ports {
		if p.State == "open" {
			m[p.Port] = p
		}
	}
	return m
}

func svcText(p report.Port) string {
	s := p.Service
	if s == nil {
		return ""
	}
	parts := []string{s.Name, s.Banner}
	if s.HTTP != nil {
		parts = append(parts, s.HTTP.Server, s.HTTP.Title)
	}
	return strings.Join(slices.DeleteFunc(parts, func(x string) bool { return x == "" }), " | ")
}

func certText(p report.Port) string {
	if p.Service == nil || p.Service.TLS == nil {
		return ""
	}
	t := p.Service.TLS
	return fmt.Sprintf("%s expires %s sha256 %.16s", t.Subject, t.NotAfter.Format("2006-01-02"), t.SHA256)
}

func deviceText(h report.Host) string {
	if h.Device == nil {
		return ""
	}
	return fmt.Sprintf("%s (%s)", h.Device.Product, h.Device.Rule)
}

// WriteText renders the comparison for people.
func WriteText(w io.Writer, r Report) error {
	for _, m := range r.Warnings {
		fmt.Fprintln(w, "warning:", m)
	}
	if len(r.Changes) == 0 {
		_, err := fmt.Fprintln(w, "no drift")
		return err
	}
	for _, c := range r.Changes {
		line := fmt.Sprintf("%-19s %s", c.Kind, c.Address)
		if c.Port != 0 {
			line += fmt.Sprintf(" %d/tcp", c.Port)
		}
		if c.Before != "" || c.After != "" {
			line += fmt.Sprintf("  %q -> %q", c.Before, c.After)
		}
		fmt.Fprintln(w, line)
	}
	_, err := fmt.Fprintf(w, "%d changes\n", len(r.Changes))
	return err
}
