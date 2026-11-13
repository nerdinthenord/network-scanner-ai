package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nerdinthenord/protolan/internal/report"
)

func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func listenPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

func TestScanJSONEndToEnd(t *testing.T) {
	port := listenPort(t)
	code, stdout, stderr := exec(t, "scan", "-format", "json", "-p", port, "127.0.0.1")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var doc report.Document
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout)
	}
	if doc.SchemaVersion != "1" || doc.Tool.Name != "protolan" || doc.Parameters.Method != "tcp-connect" {
		t.Errorf("metadata wrong: %+v %+v", doc.Tool, doc.Parameters)
	}
	if doc.Summary.HostsUp != 1 || doc.Summary.OpenPorts != 1 || len(doc.Hosts) != 1 {
		t.Fatalf("summary wrong: %+v", doc.Summary)
	}
	p := doc.Hosts[0].Ports
	if len(p) != 1 || strconv.Itoa(int(p[0].Port)) != port || p[0].State != "open" {
		t.Fatalf("ports wrong: %+v", p)
	}
}

func TestScanTextAndOutputFile(t *testing.T) {
	port := listenPort(t)
	path := filepath.Join(t.TempDir(), "report.txt")
	code, stdout, stderr := exec(t, "scan", "-o", path, "-p", port, "127.0.0.1")
	if code != exitOK || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), port+"/tcp") || !strings.Contains(string(b), "1 of 1 hosts up") {
		t.Fatalf("unexpected report:\n%s", b)
	}
}

func TestScanRefusesPublicTargetAndSendsNothing(t *testing.T) {
	code, stdout, stderr := exec(t, "scan", "8.8.8.8")
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, "--allow-public") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestScanDryRun(t *testing.T) {
	code, stdout, _ := exec(t, "scan", "-dry-run", "-p", "22,80", "-rate", "2", "192.168.1.0/30")
	if code != exitOK || !strings.Contains(stdout, "2 hosts x 2 ports = 4 probes") ||
		!strings.Contains(stdout, "nothing was sent") {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}

func TestScanAuditLog(t *testing.T) {
	port := listenPort(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if code, _, stderr := exec(t, "scan", "-audit-log", path, "-p", port, "127.0.0.1"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 audit lines, got %d:\n%s", len(lines), b)
	}
	var started, finished map[string]any
	if json.Unmarshal([]byte(lines[0]), &started) != nil || json.Unmarshal([]byte(lines[1]), &finished) != nil {
		t.Fatalf("audit lines are not JSON:\n%s", b)
	}
	if started["event"] != "scan_started" || finished["event"] != "scan_finished" || finished["probes_sent"] != float64(1) {
		t.Fatalf("audit content wrong:\n%s", b)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("audit log mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestScanFailsClosedWhenAuditLogUnwritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "audit.jsonl")
	code, stdout, stderr := exec(t, "scan", "-audit-log", path, "-p", listenPort(t), "127.0.0.1")
	if code != exitError || stdout != "" || !strings.Contains(stderr, "audit log") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"bogus"},
		{"scan"},
		{"scan", "-format", "xml", "127.0.0.1"},
		{"scan", "-p", "0", "127.0.0.1"},
		{"scan", "-timeout", "0s", "127.0.0.1"},
		{"scan", "-nope", "127.0.0.1"},
	}
	for _, args := range cases {
		if code, _, _ := exec(t, args...); code != exitUsage {
			t.Errorf("args %v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := exec(t, "version")
	if code != exitOK || !strings.HasPrefix(stdout, "protolan ") {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}
