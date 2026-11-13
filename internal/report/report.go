// Package report defines Protolan's output document and its renderers.
//
// The JSON form is a public contract: fields are only ever added within a
// schema version, never renamed or removed.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nerdinthenord/protolan/internal/scan"
)

// SchemaVersion identifies the JSON document layout.
const SchemaVersion = "1"

// Document is the complete result of one scan.
type Document struct {
	SchemaVersion string     `json:"schema_version"`
	Tool          Tool       `json:"tool"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    time.Time  `json:"finished_at"`
	Parameters    Parameters `json:"parameters"`
	Summary       Summary    `json:"summary"`
	Hosts         []Host     `json:"hosts"`
}

// Tool records what produced the document.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Parameters records how the scan was configured, so a result can be
// reproduced and audited.
type Parameters struct {
	Targets     []string `json:"targets"`
	Ports       string   `json:"ports"`
	Method      string   `json:"method"`
	TimeoutMS   int64    `json:"timeout_ms"`
	Concurrency int      `json:"concurrency"`
	RatePerSec  int      `json:"rate_per_sec"`
	AllowPublic bool     `json:"allow_public"`
}

// Summary gives totals for the run.
type Summary struct {
	HostsScanned  int `json:"hosts_scanned"`
	HostsUp       int `json:"hosts_up"`
	OpenPorts     int `json:"open_ports"`
	ProbesPlanned int `json:"probes_planned"`
	ProbesSent    int `json:"probes_sent"`
	// ProbeErrors counts probes that failed on the scanning machine itself.
	// Non-zero means the results are incomplete.
	ProbeErrors int  `json:"probe_errors"`
	Interrupted bool `json:"interrupted"`
}

// Host is one responsive address.
type Host struct {
	Address string `json:"address"`
	Ports   []Port `json:"ports"`
}

// Port is one probed port.
type Port struct {
	Port      uint16  `json:"port"`
	Protocol  string  `json:"protocol"`
	State     string  `json:"state"`
	LatencyMS float64 `json:"latency_ms"`
}

// Build converts engine results into a Document. Only hosts that answered
// are listed. Closed and filtered ports are included only when allStates is
// set; open ports are always included.
func Build(tool Tool, params Parameters, started, finished time.Time,
	results []scan.HostResult, stats scan.Stats, allStates bool) Document {

	doc := Document{
		SchemaVersion: SchemaVersion,
		Tool:          tool,
		StartedAt:     started.UTC(),
		FinishedAt:    finished.UTC(),
		Parameters:    params,
		Summary: Summary{
			HostsScanned:  len(results),
			ProbesPlanned: stats.ProbesPlanned,
			ProbesSent:    stats.ProbesSent,
			ProbeErrors:   stats.LocalErrors,
			Interrupted:   stats.Interrupted,
		},
		Hosts: []Host{},
	}
	for _, hr := range results {
		if !hr.Up {
			continue
		}
		h := Host{Address: hr.Addr.String(), Ports: []Port{}}
		for _, pr := range hr.Ports {
			if pr.State == scan.Open {
				doc.Summary.OpenPorts++
			}
			if pr.State == "" || (pr.State != scan.Open && !allStates) {
				continue
			}
			h.Ports = append(h.Ports, Port{
				Port:      pr.Port,
				Protocol:  "tcp",
				State:     string(pr.State),
				LatencyMS: float64(pr.Latency.Microseconds()) / 1000,
			})
		}
		doc.Summary.HostsUp++
		doc.Hosts = append(doc.Hosts, h)
	}
	return doc
}

// WriteJSON renders the document as indented JSON.
func WriteJSON(w io.Writer, doc Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// WriteText renders a human-readable table.
func WriteText(w io.Writer, doc Document) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tPORT\tSTATE\tLATENCY")
	for _, h := range doc.Hosts {
		if len(h.Ports) == 0 {
			fmt.Fprintf(tw, "%s\t-\tup (no open ports)\t-\n", h.Address)
			continue
		}
		for _, p := range h.Ports {
			fmt.Fprintf(tw, "%s\t%s/%s\t%s\t%s\n", h.Address,
				strconv.Itoa(int(p.Port)), p.Protocol, p.State,
				strconv.FormatFloat(p.LatencyMS, 'f', 1, 64)+"ms")
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	s := doc.Summary
	var b strings.Builder
	fmt.Fprintf(&b, "\n%d of %d hosts up, %d open ports, %d probes in %s",
		s.HostsUp, s.HostsScanned, s.OpenPorts, s.ProbesSent,
		doc.FinishedAt.Sub(doc.StartedAt).Round(10*time.Millisecond))
	if s.Interrupted {
		fmt.Fprintf(&b, " (interrupted: %d of %d probes ran)", s.ProbesSent, s.ProbesPlanned)
	}
	_, err := fmt.Fprintln(w, b.String())
	return err
}
