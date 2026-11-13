// Package identify turns observed facts about a host into a device verdict
// using declarative rules. Every verdict carries the evidence that produced
// it, so a reader can judge it rather than trust it.
package identify

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/nerdinthenord/protolan/internal/probe"
)

//go:embed rules.json
var builtinJSON []byte

// Confidence levels, weakest first.
const (
	Low    = "low"
	Medium = "medium"
	High   = "high"
)

var rank = map[string]int{Low: 1, Medium: 2, High: 3}

// Device describes what a rule concludes.
type Device struct {
	Type    string `json:"type"`
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
}

// Cond is one requirement. It is satisfied when some open port meets every
// field that is set. A Cond with only Port set means "this port is open".
// Text comparisons ignore case.
type Cond struct {
	Port               uint16 `json:"port,omitempty"`
	Service            string `json:"service,omitempty"`
	BannerContains     string `json:"banner_contains,omitempty"`
	HTTPServerContains string `json:"http_server_contains,omitempty"`
	HTTPTitleContains  string `json:"http_title_contains,omitempty"`
	TLSSubjectContains string `json:"tls_subject_contains,omitempty"`
	TLSIssuerContains  string `json:"tls_issuer_contains,omitempty"`
}

// Rule matches when every All condition holds and, if Any is non-empty, at
// least one Any condition holds.
type Rule struct {
	ID         string `json:"id"`
	Device     Device `json:"device"`
	Confidence string `json:"confidence"`
	// Note explains the reasoning or known limits of the rule.
	Note string `json:"note,omitempty"`
	All  []Cond `json:"all,omitempty"`
	Any  []Cond `json:"any,omitempty"`
	// Example is a set of facts the rule must match. It documents the rule
	// and is enforced by the test suite.
	Example []PortFact `json:"example"`
}

// PortFact is one open port and what probing learned about it.
type PortFact struct {
	Port    uint16        `json:"port"`
	Service probe.Service `json:"service"`
}

// Result is a verdict with its justification.
type Result struct {
	Device
	Confidence string   `json:"confidence"`
	Rule       string   `json:"rule"`
	Evidence   []string `json:"evidence"`
	// AlsoMatched lists other rules that matched but ranked lower.
	AlsoMatched []string `json:"also_matched,omitempty"`
}

// Load parses and validates a rule file.
func Load(data []byte) ([]Rule, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rules []Rule
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	seen := make(map[string]bool, len(rules))
	for i, r := range rules {
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("rules: entry %d (%q): %w", i, r.ID, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rules: duplicate id %q", r.ID)
		}
		seen[r.ID] = true
	}
	return rules, nil
}

func (r Rule) validate() error {
	switch {
	case r.ID == "":
		return fmt.Errorf("missing id")
	case r.Device.Type == "":
		return fmt.Errorf("missing device.type")
	case rank[r.Confidence] == 0:
		return fmt.Errorf("confidence must be low, medium or high")
	case len(r.All)+len(r.Any) == 0:
		return fmt.Errorf("needs at least one condition")
	case len(r.Example) == 0:
		return fmt.Errorf("needs an example that the rule matches")
	}
	for _, c := range append(append([]Cond{}, r.All...), r.Any...) {
		if c == (Cond{}) {
			return fmt.Errorf("empty condition")
		}
	}
	return nil
}

// Builtin returns the rules compiled into the binary.
var Builtin = sync.OnceValues(func() ([]Rule, error) { return Load(builtinJSON) })

// Merge appends extra rules, rejecting ids that collide with base.
func Merge(base, extra []Rule) ([]Rule, error) {
	seen := make(map[string]bool, len(base))
	for _, r := range base {
		seen[r.ID] = true
	}
	out := append([]Rule{}, base...)
	for _, r := range extra {
		if seen[r.ID] {
			return nil, fmt.Errorf("rules: id %q is already defined", r.ID)
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out, nil
}

type match struct {
	rule     Rule
	evidence []string
}

// Identify returns the best-ranked matching rule, or nil when none match.
// Ranking is by confidence, then by number of conditions (more specific
// first), then by id so the outcome is deterministic.
func Identify(facts []PortFact, rules []Rule) *Result {
	var matches []match
	for _, r := range rules {
		if ev, ok := r.match(facts); ok {
			matches = append(matches, match{r, ev})
		}
	}
	if len(matches) == 0 {
		return nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		a, b := matches[i].rule, matches[j].rule
		if rank[a.Confidence] != rank[b.Confidence] {
			return rank[a.Confidence] > rank[b.Confidence]
		}
		if la, lb := len(a.All)+len(a.Any), len(b.All)+len(b.Any); la != lb {
			return la > lb
		}
		return a.ID < b.ID
	})
	best := matches[0]
	res := &Result{
		Device:     best.rule.Device,
		Confidence: best.rule.Confidence,
		Rule:       best.rule.ID,
		Evidence:   best.evidence,
	}
	for _, m := range matches[1:] {
		res.AlsoMatched = append(res.AlsoMatched, m.rule.ID)
	}
	return res
}

func (r Rule) match(facts []PortFact) ([]string, bool) {
	var evidence []string
	for _, c := range r.All {
		ev, ok := c.match(facts)
		if !ok {
			return nil, false
		}
		evidence = append(evidence, ev)
	}
	if len(r.Any) > 0 {
		hit := false
		for _, c := range r.Any {
			if ev, ok := c.match(facts); ok {
				evidence = append(evidence, ev)
				hit = true
			}
		}
		if !hit {
			return nil, false
		}
	}
	return evidence, true
}

// match returns a human-readable statement of what satisfied the condition.
func (c Cond) match(facts []PortFact) (string, bool) {
	for _, f := range facts {
		if c.Port != 0 && c.Port != f.Port {
			continue
		}
		var parts []string
		ok := true
		check := func(want, got, label string) {
			if want == "" || !ok {
				return
			}
			if got == "" || !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
				ok = false
				return
			}
			parts = append(parts, fmt.Sprintf("%s contains %q (%q)", label, want, got))
		}
		if c.Service != "" {
			if !strings.EqualFold(c.Service, f.Service.Name) {
				continue
			}
			parts = append(parts, "speaks "+f.Service.Name)
		}
		var server, title, subject, issuer string
		if f.Service.HTTP != nil {
			server, title = f.Service.HTTP.Server, f.Service.HTTP.Title
		}
		if f.Service.TLS != nil {
			subject, issuer = f.Service.TLS.Subject, f.Service.TLS.Issuer
		}
		check(c.BannerContains, f.Service.Banner, "banner")
		check(c.HTTPServerContains, server, "HTTP Server header")
		check(c.HTTPTitleContains, title, "page title")
		check(c.TLSSubjectContains, subject, "certificate subject")
		check(c.TLSIssuerContains, issuer, "certificate issuer")
		if !ok {
			continue
		}
		if len(parts) == 0 {
			parts = []string{"is open"}
		}
		return fmt.Sprintf("port %d/tcp %s", f.Port, strings.Join(parts, "; ")), true
	}
	return "", false
}
