// Package scan is the probing engine: an unprivileged TCP connect scanner
// with bounded concurrency and a global rate limit.
//
// It uses ordinary operating-system sockets, so it needs no root privileges
// and no packet-capture driver.
package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// State is what a probe concluded about one port.
type State string

const (
	// Open: the TCP handshake completed.
	Open State = "open"
	// Closed: the host actively refused the connection.
	Closed State = "closed"
	// Filtered: no answer within the timeout, or the network reported the
	// destination unreachable. The port may be firewalled or the host absent.
	Filtered State = "filtered"
)

// Defaults used when a Config field is left at zero.
const (
	DefaultTimeout = 1500 * time.Millisecond
	// DefaultConcurrency stays well under the 256 open-file limit that
	// macOS gives processes by default.
	DefaultConcurrency = 128
)

// Dialer is the subset of net.Dialer the engine needs. Tests substitute it.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Config tunes a run.
type Config struct {
	// Timeout bounds each connection attempt.
	Timeout time.Duration
	// Concurrency bounds simultaneous connection attempts.
	Concurrency int
	// Rate caps new connection attempts per second across the whole run.
	// Zero means no cap beyond Concurrency.
	Rate int
	// Dialer overrides the network dialer. Nil uses net.Dialer.
	Dialer Dialer
}

// PortResult is the outcome for one port on one host.
type PortResult struct {
	Port    uint16
	State   State
	Latency time.Duration // time until the outcome was known
}

// HostResult groups the outcomes for one address.
type HostResult struct {
	Addr netip.Addr
	// Up is true when at least one port answered, open or closed. A host
	// that silently drops every probe is indistinguishable from an absent
	// one and is reported as not up.
	Up    bool
	Ports []PortResult // same order as the ports passed to Run
}

// Stats summarises a run.
type Stats struct {
	ProbesPlanned int
	ProbesSent    int
	// Interrupted is true when the context ended before every probe ran.
	// Ports that were never probed have an empty State.
	Interrupted bool
	// LocalErrors counts probes that failed because of this machine rather
	// than the target, such as running out of file descriptors. Those probes
	// are recorded as filtered, so a non-zero count means the results are
	// incomplete.
	LocalErrors     int
	FirstLocalError string
}

type job struct{ host, port int }

// Run probes every port on every target. It always returns the results
// gathered so far; when ctx ends early, Stats.Interrupted is set.
func Run(ctx context.Context, targets []netip.Addr, ports []uint16, cfg Config) ([]HostResult, Stats) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{}
	}

	results := make([]HostResult, len(targets))
	for i, a := range targets {
		results[i] = HostResult{Addr: a, Ports: make([]PortResult, len(ports))}
		for j, p := range ports {
			results[i].Ports[j].Port = p
		}
	}
	stats := Stats{ProbesPlanned: len(targets) * len(ports)}
	if stats.ProbesPlanned == 0 {
		return results, stats
	}

	var lim *limiter
	if cfg.Rate > 0 {
		lim = &limiter{interval: time.Second / time.Duration(cfg.Rate)}
	}

	jobs := make(chan job)
	var mu sync.Mutex // guards the counters in stats

	workers := min(cfg.Concurrency, stats.ProbesPlanned)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Each (host, port) slot is written by exactly one worker.
				r := &results[j.host].Ports[j.port]
				var localErr error
				r.State, r.Latency, localErr = probe(ctx, cfg, targets[j.host], r.Port)
				mu.Lock()
				stats.ProbesSent++
				if localErr != nil {
					if stats.LocalErrors == 0 {
						stats.FirstLocalError = localErr.Error()
					}
					stats.LocalErrors++
				}
				mu.Unlock()
			}
		}()
	}

	// Iterate ports in the outer loop so consecutive probes land on
	// different hosts, which spreads load instead of hammering one device.
dispatch:
	for p := range ports {
		for h := range targets {
			if lim.wait(ctx) != nil {
				break dispatch
			}
			select {
			case jobs <- job{host: h, port: p}:
			case <-ctx.Done():
				break dispatch
			}
		}
	}
	close(jobs)
	wg.Wait()

	stats.Interrupted = ctx.Err() != nil && stats.ProbesSent < stats.ProbesPlanned
	for i := range results {
		for _, pr := range results[i].Ports {
			if pr.State == Open || pr.State == Closed {
				results[i].Up = true
				break
			}
		}
	}
	return results, stats
}

// probe attempts one connection. localErr is non-nil when the attempt failed
// for a reason on this machine, in which case the state says nothing about
// the target.
func probe(ctx context.Context, cfg Config, addr netip.Addr, port uint16) (state State, latency time.Duration, localErr error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	start := time.Now()
	conn, err := cfg.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
	elapsed := time.Since(start)
	switch {
	case err == nil:
		_ = conn.Close()
		return Open, elapsed, nil
	case errors.Is(err, syscall.ECONNREFUSED):
		return Closed, elapsed, nil
	case isLocal(err):
		return Filtered, elapsed, err
	default:
		return Filtered, elapsed, nil
	}
}

// isLocal reports whether a dial error originated on the scanning machine.
func isLocal(err error) bool {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.EADDRNOTAVAIL, syscall.EACCES, syscall.EPERM} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// limiter spaces events at a fixed interval. A nil limiter never waits.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func (l *limiter) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil || l == nil {
		return err
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	d := time.Until(at)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
