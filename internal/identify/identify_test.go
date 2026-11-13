package identify

import (
	"strings"
	"testing"

	"github.com/nerdinthenord/protolan/internal/probe"
)

func builtin(t *testing.T) []Rule {
	t.Helper()
	rules, err := Builtin()
	if err != nil {
		t.Fatalf("built-in rules are invalid: %v", err)
	}
	return rules
}

// Every built-in rule must match its own documented example.
func TestBuiltinRulesMatchTheirExamples(t *testing.T) {
	rules := builtin(t)
	if len(rules) == 0 {
		t.Fatal("no built-in rules")
	}
	for _, r := range rules {
		ev, ok := r.match(r.Example)
		if !ok {
			t.Errorf("rule %q does not match its own example", r.ID)
		}
		if ok && len(ev) == 0 {
			t.Errorf("rule %q matched without evidence", r.ID)
		}
	}
}

func port(p uint16) PortFact { return PortFact{Port: p} }

func TestIdentifyRanking(t *testing.T) {
	rules := builtin(t)

	// A banner match (high) outranks a port-pair match (low) on one host.
	facts := []PortFact{
		{Port: 22, Service: probe.Service{Name: "ssh", Banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"}},
		port(53), port(80),
	}
	got := Identify(facts, rules)
	if got == nil || got.Rule != "ssh-ubuntu" || got.Confidence != High {
		t.Fatalf("got %+v", got)
	}
	if len(got.AlsoMatched) != 1 || got.AlsoMatched[0] != "ports-gateway" {
		t.Errorf("also_matched = %v", got.AlsoMatched)
	}
	if len(got.Evidence) != 1 || !strings.Contains(got.Evidence[0], "port 22/tcp") ||
		!strings.Contains(got.Evidence[0], `banner contains "Ubuntu"`) {
		t.Errorf("evidence = %q", got.Evidence)
	}

	// Among equal confidence, the more specific rule wins.
	got = Identify([]PortFact{port(631), port(9100)}, rules)
	if got == nil || got.Rule != "ports-printer" || got.AlsoMatched[0] != "ports-raw-print" {
		t.Fatalf("got %+v", got)
	}
}

func TestIdentifyFromRealScanShapes(t *testing.T) {
	rules := builtin(t)
	tests := []struct {
		name  string
		ports []uint16
		want  string
	}{
		{"cast device", []uint16{8008, 8009, 8443, 9000, 10001}, "ports-google-cast"},
		{"ios device", []uint16{53, 5000, 7000, 7100, 49152, 62078}, "ports-apple-ios"},
		{"airplay only", []uint16{5000, 7000}, "ports-apple-airplay"},
		{"tuya", []uint16{6668}, "ports-tuya"},
		{"kasa", []uint16{9999}, "ports-tplink-kasa"},
		{"nothing recognisable", []uint16{22, 80}, ""},
		{"no open ports", nil, ""},
	}
	for _, tc := range tests {
		var facts []PortFact
		for _, p := range tc.ports {
			facts = append(facts, port(p))
		}
		got := Identify(facts, rules)
		switch {
		case tc.want == "" && got != nil:
			t.Errorf("%s: got %q, want no verdict", tc.name, got.Rule)
		case tc.want != "" && (got == nil || got.Rule != tc.want):
			t.Errorf("%s: got %+v, want %q", tc.name, got, tc.want)
		}
	}
}

func TestCondSemantics(t *testing.T) {
	web := PortFact{Port: 8080, Service: probe.Service{Name: "http", HTTP: &probe.HTTP{Server: "nginx/1.24", Title: "Admin Console"}}}
	tlsFact := PortFact{Port: 443, Service: probe.Service{Name: "https", TLS: &probe.TLS{Subject: "router.lan", Issuer: "Acme Root"}}}
	facts := []PortFact{web, tlsFact}

	tests := []struct {
		name string
		cond Cond
		want bool
	}{
		{"case-insensitive header", Cond{HTTPServerContains: "NGINX"}, true},
		{"title", Cond{HTTPTitleContains: "admin"}, true},
		{"fields must hold on the same port", Cond{HTTPServerContains: "nginx", TLSSubjectContains: "router"}, false},
		{"port restricts the search", Cond{Port: 443, HTTPServerContains: "nginx"}, false},
		{"port and field together", Cond{Port: 8080, Service: "HTTP", HTTPServerContains: "nginx"}, true},
		{"tls issuer", Cond{TLSIssuerContains: "acme"}, true},
		{"missing data never matches", Cond{BannerContains: "x"}, false},
		{"closed port", Cond{Port: 22}, false},
	}
	for _, tc := range tests {
		if _, got := tc.cond.match(facts); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestLoadRejectsBadRules(t *testing.T) {
	ex := `"example":[{"port":1,"service":{}}]`
	bad := map[string]string{
		"not json":        `{`,
		"unknown field":   `[{"id":"a","device":{"type":"x"},"confidence":"low","all":[{"port":1}],"typo":1,` + ex + `}]`,
		"missing id":      `[{"device":{"type":"x"},"confidence":"low","all":[{"port":1}],` + ex + `}]`,
		"missing type":    `[{"id":"a","device":{},"confidence":"low","all":[{"port":1}],` + ex + `}]`,
		"bad confidence":  `[{"id":"a","device":{"type":"x"},"confidence":"certain","all":[{"port":1}],` + ex + `}]`,
		"no conditions":   `[{"id":"a","device":{"type":"x"},"confidence":"low",` + ex + `}]`,
		"empty condition": `[{"id":"a","device":{"type":"x"},"confidence":"low","all":[{}],` + ex + `}]`,
		"missing example": `[{"id":"a","device":{"type":"x"},"confidence":"low","all":[{"port":1}]}]`,
		"duplicate id":    `[{"id":"a","device":{"type":"x"},"confidence":"low","all":[{"port":1}],` + ex + `},{"id":"a","device":{"type":"x"},"confidence":"low","all":[{"port":1}],` + ex + `}]`,
	}
	for name, data := range bad {
		if _, err := Load([]byte(data)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestMerge(t *testing.T) {
	base := builtin(t)
	extra := []Rule{{ID: "custom", Device: Device{Type: "x"}, Confidence: High, All: []Cond{{Port: 1}}}}
	merged, err := Merge(base, extra)
	if err != nil || len(merged) != len(base)+1 {
		t.Fatalf("merge: %d rules, err %v", len(merged), err)
	}
	if _, err := Merge(base, []Rule{{ID: base[0].ID}}); err == nil {
		t.Fatal("colliding id must be rejected")
	}
}
