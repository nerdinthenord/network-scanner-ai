// Package audit appends one JSON line per scan to an operator-chosen file,
// recording who scanned what and when.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"time"
)

// Entry is one audit record.
type Entry struct {
	Time        time.Time `json:"time"`
	Event       string    `json:"event"` // "scan_started" or "scan_finished"
	User        string    `json:"user"`
	Host        string    `json:"host"`
	ToolVersion string    `json:"tool_version"`
	Targets     []string  `json:"targets"`
	Ports       string    `json:"ports"`
	HostCount   int       `json:"host_count"`
	AllowPublic bool      `json:"allow_public"`
	ProbesSent  *int      `json:"probes_sent,omitempty"`
	Interrupted *bool     `json:"interrupted,omitempty"`
}

// Identity fills in the invoking user and machine name, best effort.
func (e *Entry) Identity() {
	if u, err := user.Current(); err == nil {
		e.User = u.Username
	}
	if h, err := os.Hostname(); err == nil {
		e.Host = h
	}
}

// Append writes the entry as a single line. The file is created with
// owner-only permissions if it does not exist.
func Append(path string, e Entry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("audit log: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}
