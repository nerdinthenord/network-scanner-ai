package drift

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nerdinthenord/protolan/internal/identify"
	"github.com/nerdinthenord/protolan/internal/probe"
	"github.com/nerdinthenord/protolan/internal/report"
)

func doc(hosts ...report.Host) report.Document {
	return report.Document{Parameters: report.Parameters{Targets: []string{"10.0.0.0/24"}, Ports: "common", Identify: true}, Hosts: hosts}
}

func open(port uint16, s *probe.Service) report.Port {
	return report.Port{Port: port, State: "open", Service: s}
}

func TestCompare(t *testing.T) {
	old := doc(
		report.Host{Address: "10.0.0.9", Ports: []report.Port{open(22, nil)}},
		report.Host{Address: "10.0.0.10", Device: &identify.Result{Device: identify.Device{Product: "A"}, Rule: "ra"},
			Ports: []report.Port{
				open(22, &probe.Service{Name: "ssh", Banner: "SSH-2.0-OpenSSH_8"}),
				open(23, nil),
				open(443, &probe.Service{Name: "https", TLS: &probe.TLS{Subject: "x", SHA256: "aaaa"}}),
				{Port: 80, State: "closed"},
			}},
	)
	cur := doc(
		report.Host{Address: "10.0.0.2", Ports: []report.Port{open(80, nil)}},
		report.Host{Address: "10.0.0.10", Device: &identify.Result{Device: identify.Device{Product: "B"}, Rule: "rb"},
			Ports: []report.Port{
				open(22, &probe.Service{Name: "ssh", Banner: "SSH-2.0-OpenSSH_9"}),
				open(443, &probe.Service{Name: "https", TLS: &probe.TLS{Subject: "x", SHA256: "bbbb"}}),
				open(8080, nil),
			}},
	)
	r := Compare(old, cur)
	var got []string
	for _, c := range r.Changes {
		got = append(got, c.Kind+"@"+c.Address+":"+string(rune('0'+c.Port%10)))
	}
	want := "host_new@10.0.0.2:0 host_gone@10.0.0.9:0 device_changed@10.0.0.10:0 service_changed@10.0.0.10:2 " +
		"port_closed@10.0.0.10:3 certificate_changed@10.0.0.10:3 port_opened@10.0.0.10:0"
	if strings.Join(got, " ") != want {
		t.Fatalf("changes:\n got %v\nwant %v", strings.Join(got, " "), want)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("unexpected warnings %v", r.Warnings)
	}
	var b bytes.Buffer
	if err := WriteText(&b, r); err != nil || !strings.Contains(b.String(), "7 changes") {
		t.Fatalf("text: %v\n%s", err, b.String())
	}
}

func TestCompareNoDriftAndWarnings(t *testing.T) {
	a := doc(report.Host{Address: "10.0.0.1", Ports: []report.Port{open(22, &probe.Service{Name: "ssh"})}})
	if r := Compare(a, a); len(r.Changes) != 0 || len(r.Warnings) != 0 {
		t.Fatalf("identical scans: %+v", r)
	}
	b := doc(report.Host{Address: "10.0.0.1", Ports: []report.Port{open(22, nil)}})
	b.Parameters.Ports, b.Parameters.Identify, b.Summary.Interrupted = "22", false, true
	r := Compare(a, b)
	if len(r.Warnings) != 3 || len(r.Changes) != 0 {
		t.Fatalf("want 3 warnings and no service change when identification differs: %+v", r)
	}
}
