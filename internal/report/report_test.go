package report

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nerdinthenord/protolan/internal/scan"
)

func sample() ([]scan.HostResult, scan.Stats) {
	return []scan.HostResult{
		{Addr: netip.MustParseAddr("10.0.0.1"), Up: true, Ports: []scan.PortResult{
			{Port: 22, State: scan.Open, Latency: 1500 * time.Microsecond},
			{Port: 23, State: scan.Closed},
			{Port: 80, State: scan.Filtered},
			{Port: 81}, // never probed
		}},
		{Addr: netip.MustParseAddr("10.0.0.2"), Up: true, Ports: []scan.PortResult{{Port: 22, State: scan.Closed}}},
		{Addr: netip.MustParseAddr("10.0.0.3"), Ports: []scan.PortResult{{Port: 22, State: scan.Filtered}}},
	}, scan.Stats{ProbesPlanned: 6, ProbesSent: 5, Interrupted: true}
}

func TestBuild(t *testing.T) {
	res, stats := sample()
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))

	doc := Build(Tool{Name: "protolan"}, Parameters{}, t0, t0.Add(time.Second), res, stats, false)
	if doc.SchemaVersion != SchemaVersion || doc.StartedAt.Location() != time.UTC {
		t.Errorf("schema %q, location %v", doc.SchemaVersion, doc.StartedAt.Location())
	}
	s := doc.Summary
	if s.HostsScanned != 3 || s.HostsUp != 2 || s.OpenPorts != 1 || !s.Interrupted {
		t.Fatalf("summary = %+v", s)
	}
	if len(doc.Hosts) != 2 || len(doc.Hosts[0].Ports) != 1 || doc.Hosts[0].Ports[0].LatencyMS != 1.5 {
		t.Fatalf("default view should list only open ports: %+v", doc.Hosts)
	}
	if doc.Hosts[1].Ports == nil {
		t.Fatal("ports must encode as [] rather than null")
	}

	all := Build(Tool{}, Parameters{}, t0, t0, res, stats, true)
	if len(all.Hosts[0].Ports) != 3 {
		t.Fatalf("all-states view should list probed ports only: %+v", all.Hosts[0].Ports)
	}
}

func TestWriteText(t *testing.T) {
	res, stats := sample()
	t0 := time.Now()
	var b bytes.Buffer
	if err := WriteText(&b, Build(Tool{}, Parameters{}, t0, t0.Add(2*time.Second), res, stats, false)); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"22/tcp", "up (no open ports)", "2 of 3 hosts up", "interrupted: 5 of 6"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q:\n%s", want, out)
		}
	}
}

func TestEmptyHostsEncodeAsArray(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, Build(Tool{}, Parameters{}, time.Now(), time.Now(), nil, scan.Stats{}, false)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"hosts": []`) {
		t.Fatalf("hosts should be [] when nothing is up:\n%s", b.String())
	}
}
