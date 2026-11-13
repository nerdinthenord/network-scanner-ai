// Command protolan is a lightweight network exposure scanner.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/nerdinthenord/protolan/internal/audit"
	"github.com/nerdinthenord/protolan/internal/drift"
	"github.com/nerdinthenord/protolan/internal/identify"
	"github.com/nerdinthenord/protolan/internal/ports"
	"github.com/nerdinthenord/protolan/internal/probe"
	"github.com/nerdinthenord/protolan/internal/report"
	"github.com/nerdinthenord/protolan/internal/scan"
	"github.com/nerdinthenord/protolan/internal/target"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.3.0-dev"

// Exit codes. They are part of the CLI contract.
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitDrift       = 3
	exitInterrupted = 130
)

const usage = `protolan - lightweight network exposure scanner

Usage:
  protolan scan [flags] <target>...
  protolan diff [-format text|json] <old.json> <new.json>
  protolan rules
  protolan version

Targets are IP addresses, CIDR prefixes (192.168.1.0/24) or ranges
(192.168.1.10-192.168.1.50). Flags must come before targets.

Only scan networks you own or are authorized in writing to test.
Run "protolan scan -h" for flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "rules":
		return runRules(stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "protolan", version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "protolan: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("protolan scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		portSpec    = fs.String("ports", "common", `ports to probe: "common", "all", or a list such as 22,80,8000-8100`)
		timeout     = fs.Duration("timeout", scan.DefaultTimeout, "per-connection timeout")
		concurrency = fs.Int("concurrency", scan.DefaultConcurrency, "maximum simultaneous connection attempts")
		rate        = fs.Int("rate", 500, "maximum new connection attempts per second (0 = unlimited)")
		maxHosts    = fs.Int("max-hosts", target.DefaultMaxHosts, "refuse to scan more than this many addresses")
		allowPublic = fs.Bool("allow-public", false, "permit public (non-private) addresses; requires authorization")
		format      = fs.String("format", "text", `output format: "text" or "json"`)
		outPath     = fs.String("output", "", "write the report to this file instead of stdout")
		allStates   = fs.Bool("all-states", false, "also report closed and filtered ports on responsive hosts")
		dryRun      = fs.Bool("dry-run", false, "validate targets and print the plan without sending anything")
		historyDir  = fs.String("history", "", "save each scan as JSON in this directory and report drift from the previous one")
		failOnDrift = fs.Bool("fail-on-drift", false, "with -history, exit 3 when the scan differs from the previous one")
		noIdentify  = fs.Bool("no-identify", false, "do not probe open ports for service details or identify devices")
		rulesPath   = fs.String("rules", "", "JSON file of additional identification rules")
		auditPath   = fs.String("audit-log", os.Getenv("PROTOLAN_AUDIT_LOG"), "append a JSON audit record per scan to this file (env PROTOLAN_AUDIT_LOG)")
	)
	fs.StringVar(portSpec, "p", "common", "shorthand for -ports")
	fs.StringVar(outPath, "o", "", "shorthand for -output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	fail := func(code int, err error) int {
		fmt.Fprintln(stderr, "protolan:", err)
		return code
	}

	if *format != "text" && *format != "json" {
		return fail(exitUsage, fmt.Errorf("unknown format %q", *format))
	}
	if *timeout <= 0 || *concurrency <= 0 || *rate < 0 || *maxHosts <= 0 {
		return fail(exitUsage, errors.New("timeout, concurrency and max-hosts must be positive; rate must not be negative"))
	}
	specs := fs.Args()
	addrs, err := target.Expand(specs, target.Options{AllowPublic: *allowPublic, MaxHosts: *maxHosts})
	if err != nil {
		return fail(exitUsage, err)
	}
	portList, err := ports.Parse(*portSpec)
	if err != nil {
		return fail(exitUsage, err)
	}

	var rules []identify.Rule
	if !*noIdentify {
		if rules, err = loadRules(*rulesPath); err != nil {
			return fail(exitUsage, err)
		}
	}

	planned := len(addrs) * len(portList)
	if *dryRun {
		fmt.Fprintf(stdout, "dry run: %d hosts x %d ports = %d probes", len(addrs), len(portList), planned)
		if *rate > 0 {
			fmt.Fprintf(stdout, ", at least %s at %d/s",
				(time.Duration(planned) * time.Second / time.Duration(*rate)).Round(time.Second), *rate)
		}
		fmt.Fprintln(stdout, "; nothing was sent")
		return exitOK
	}

	entry := audit.Entry{
		Event:       "scan_started",
		ToolVersion: version,
		Targets:     specs,
		Ports:       *portSpec,
		HostCount:   len(addrs),
		AllowPublic: *allowPublic,
	}
	entry.Identity()
	if *auditPath != "" {
		// Fail closed: if the scan cannot be recorded, it does not run.
		entry.Time = time.Now().UTC()
		if err := audit.Append(*auditPath, entry); err != nil {
			return fail(exitError, err)
		}
	}

	started := time.Now()
	results, stats := scan.Run(ctx, addrs, portList, scan.Config{
		Timeout:     *timeout,
		Concurrency: *concurrency,
		Rate:        *rate,
	})

	opt := report.Options{AllStates: *allStates}
	if !*noIdentify && !stats.Interrupted {
		opt.Services, opt.Devices = identifyHosts(ctx, results, rules, probe.Config{UserAgent: "protolan/" + version})
	}
	finished := time.Now()

	if *auditPath != "" {
		entry.Event, entry.Time = "scan_finished", finished.UTC()
		entry.ProbesSent, entry.Interrupted = &stats.ProbesSent, &stats.Interrupted
		if err := audit.Append(*auditPath, entry); err != nil {
			fmt.Fprintln(stderr, "protolan:", err)
		}
	}

	doc := report.Build(
		report.Tool{Name: "protolan", Version: version},
		report.Parameters{
			Targets:     specs,
			Ports:       *portSpec,
			Method:      "tcp-connect",
			TimeoutMS:   timeout.Milliseconds(),
			Concurrency: *concurrency,
			RatePerSec:  *rate,
			AllowPublic: *allowPublic,
			Identify:    !*noIdentify,
		},
		started, finished, results, stats, opt)

	render := report.WriteText
	if *format == "json" {
		render = report.WriteJSON
	}
	if *outPath == "" {
		err = render(stdout, doc)
	} else {
		err = writeFile(*outPath, func(w io.Writer) error { return render(w, doc) })
	}
	if err != nil {
		return fail(exitError, err)
	}
	drifted := false
	if *historyDir != "" {
		if drifted, err = recordHistory(*historyDir, doc, stderr); err != nil {
			return fail(exitError, err)
		}
	}
	if stats.LocalErrors > 0 {
		fmt.Fprintf(stderr, "protolan: warning: %d probes failed on this machine (first: %s); results are incomplete, try a lower -concurrency\n",
			stats.LocalErrors, stats.FirstLocalError)
	}
	if stats.Interrupted {
		return exitInterrupted
	}
	if drifted && *failOnDrift {
		return exitDrift
	}
	return exitOK
}

// recordHistory saves doc in dir and, when an earlier scan exists there,
// writes the drift from it to w. It reports whether anything changed.
func recordHistory(dir string, doc report.Document, w io.Writer) (bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	earlier, _ := filepath.Glob(filepath.Join(dir, "scan-*.json"))
	sort.Strings(earlier)

	name := "scan-" + doc.StartedAt.Format("20060102T150405.000000000Z") + ".json"
	if err := writeFile(filepath.Join(dir, name), func(f io.Writer) error { return report.WriteJSON(f, doc) }); err != nil {
		return false, err
	}
	if len(earlier) == 0 {
		fmt.Fprintln(w, "protolan: first scan saved to history; nothing to compare yet")
		return false, nil
	}
	prev, err := report.Read(earlier[len(earlier)-1])
	if err != nil {
		return false, err
	}
	d := drift.Compare(prev, doc)
	fmt.Fprintf(w, "drift since %s:\n", prev.StartedAt.Format(time.RFC3339))
	return len(d.Changes) > 0, drift.WriteText(w, d)
}

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("protolan diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", `output format: "text" or "json"`)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 2 || (*format != "text" && *format != "json") {
		fmt.Fprintln(stderr, "usage: protolan diff [-format text|json] <old.json> <new.json>")
		return exitUsage
	}
	var docs [2]report.Document
	for i, path := range fs.Args() {
		var err error
		if docs[i], err = report.Read(path); err != nil {
			fmt.Fprintln(stderr, "protolan:", err)
			return exitError
		}
	}
	d := drift.Compare(docs[0], docs[1])
	var err error
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(d)
	} else {
		err = drift.WriteText(stdout, d)
	}
	if err != nil {
		return exitError
	}
	if len(d.Changes) > 0 {
		return exitDrift
	}
	return exitOK
}

// writeFile creates path with owner-only permissions (reports describe a
// network's exposure) and reports write and close errors alike.
func writeFile(path string, write func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// loadRules returns the built-in rules plus any from an operator file.
func loadRules(path string) ([]identify.Rule, error) {
	rules, err := identify.Builtin()
	if err != nil || path == "" {
		return rules, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	extra, err := identify.Load(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return identify.Merge(rules, extra)
}

// identifyHosts probes every open port, then applies the rules per host.
func identifyHosts(ctx context.Context, results []scan.HostResult, rules []identify.Rule,
	cfg probe.Config) (map[probe.Target]probe.Service, map[netip.Addr]*identify.Result) {

	var targets []probe.Target
	for _, hr := range results {
		for _, pr := range hr.Ports {
			if pr.State == scan.Open {
				targets = append(targets, probe.Target{Addr: hr.Addr, Port: pr.Port})
			}
		}
	}
	services := probe.All(ctx, targets, cfg)

	devices := make(map[netip.Addr]*identify.Result)
	for _, hr := range results {
		var facts []identify.PortFact
		for _, pr := range hr.Ports {
			if pr.State == scan.Open {
				facts = append(facts, identify.PortFact{
					Port:    pr.Port,
					Service: services[probe.Target{Addr: hr.Addr, Port: pr.Port}],
				})
			}
		}
		if res := identify.Identify(facts, rules); res != nil {
			devices[hr.Addr] = res
		}
	}
	return services, devices
}

func runRules(stdout, stderr io.Writer) int {
	rules, err := identify.Builtin()
	if err != nil {
		fmt.Fprintln(stderr, "protolan:", err)
		return exitError
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tCONFIDENCE\tTYPE\tPRODUCT")
	for _, r := range rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Confidence, r.Device.Type, r.Device.Product)
	}
	if err := tw.Flush(); err != nil {
		return exitError
	}
	return exitOK
}
