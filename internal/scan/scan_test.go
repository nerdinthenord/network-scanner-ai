package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// listen opens a loopback listener and returns its port.
func listen(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// closedPort returns a loopback port that nothing is listening on.
func closedPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return port
}

var loopback = []netip.Addr{netip.MustParseAddr("127.0.0.1")}

func TestRunOpenAndClosed(t *testing.T) {
	open, closed := listen(t), closedPort(t)
	res, stats := Run(context.Background(), loopback, []uint16{open, closed}, Config{Timeout: 2 * time.Second})

	if stats.ProbesPlanned != 2 || stats.ProbesSent != 2 || stats.Interrupted {
		t.Fatalf("stats = %+v", stats)
	}
	if len(res) != 1 || !res[0].Up {
		t.Fatalf("host not reported up: %+v", res)
	}
	p := res[0].Ports
	if p[0].Port != open || p[0].State != Open {
		t.Errorf("open port: %+v", p[0])
	}
	if p[1].Port != closed || p[1].State != Closed {
		t.Errorf("closed port: %+v", p[1])
	}
}

// fakeDialer answers from a table instead of the network.
type fakeDialer struct {
	fn    func(ctx context.Context, address string) error
	calls atomic.Int64
}

func (f *fakeDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	f.calls.Add(1)
	if err := f.fn(ctx, address); err != nil {
		return nil, err
	}
	c, peer := net.Pipe()
	_ = peer.Close()
	return c, nil
}

func TestRunFilteredHostIsNotUp(t *testing.T) {
	d := &fakeDialer{fn: func(ctx context.Context, _ string) error {
		<-ctx.Done() // never answers
		return ctx.Err()
	}}
	res, _ := Run(context.Background(), loopback, []uint16{80, 443}, Config{Timeout: 30 * time.Millisecond, Dialer: d})
	if res[0].Up {
		t.Fatal("a host that never answers must not be reported up")
	}
	for _, p := range res[0].Ports {
		if p.State != Filtered {
			t.Errorf("port %d state = %q, want filtered", p.Port, p.State)
		}
	}
}

func TestRunUnreachableIsFiltered(t *testing.T) {
	d := &fakeDialer{fn: func(context.Context, string) error {
		return &net.OpError{Op: "dial", Err: errors.New("no route to host")}
	}}
	res, _ := Run(context.Background(), loopback, []uint16{22}, Config{Dialer: d})
	if res[0].Ports[0].State != Filtered || res[0].Up {
		t.Fatalf("got %+v", res[0])
	}
}

func TestRunCoversEveryHostPortPair(t *testing.T) {
	targets := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("fd00::1"),
	}
	ports := []uint16{22, 80, 443, 8080}
	d := &fakeDialer{fn: func(_ context.Context, address string) error {
		if address == "10.0.0.2:80" || address == "[fd00::1]:443" {
			return nil
		}
		return &net.OpError{Op: "dial", Err: errors.New("timeout")}
	}}
	res, stats := Run(context.Background(), targets, ports, Config{Concurrency: 3, Dialer: d})

	if got := d.calls.Load(); got != 12 || stats.ProbesSent != 12 {
		t.Fatalf("dials = %d, sent = %d; want 12", got, stats.ProbesSent)
	}
	if res[0].Up || !res[1].Up || !res[2].Up {
		t.Fatalf("up flags wrong: %v %v %v", res[0].Up, res[1].Up, res[2].Up)
	}
	if res[1].Ports[1].State != Open || res[2].Ports[2].State != Open {
		t.Fatal("open ports landed in the wrong slots")
	}
}

func TestRunHonoursConcurrencyLimit(t *testing.T) {
	var inflight, peak atomic.Int64
	d := &fakeDialer{fn: func(context.Context, string) error {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		inflight.Add(-1)
		return nil
	}}
	ports := make([]uint16, 40)
	for i := range ports {
		ports[i] = uint16(1000 + i)
	}
	Run(context.Background(), loopback, ports, Config{Concurrency: 4, Dialer: d})
	if got := peak.Load(); got > 4 {
		t.Fatalf("peak concurrency %d exceeded the limit of 4", got)
	}
}

func TestRunHonoursRateLimit(t *testing.T) {
	d := &fakeDialer{fn: func(context.Context, string) error { return nil }}
	ports := []uint16{1, 2, 3, 4, 5, 6}
	start := time.Now()
	Run(context.Background(), loopback, ports, Config{Rate: 50, Dialer: d}) // 20ms apart
	// Six probes at 50/s need at least five intervals = 100ms.
	if elapsed := time.Since(start); elapsed < 95*time.Millisecond {
		t.Fatalf("6 probes at 50/s finished in %s; rate limit not applied", elapsed)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &fakeDialer{}
	d.fn = func(context.Context, string) error {
		if d.calls.Load() == 3 {
			cancel()
		}
		return nil
	}
	ports := make([]uint16, 500)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	res, stats := Run(ctx, loopback, ports, Config{Concurrency: 1, Dialer: d})

	if !stats.Interrupted || stats.ProbesSent >= stats.ProbesPlanned {
		t.Fatalf("stats = %+v; want an interrupted partial run", stats)
	}
	if !res[0].Up || res[0].Ports[0].State != Open {
		t.Fatal("results gathered before cancellation were lost")
	}
	if res[0].Ports[499].State != "" {
		t.Fatal("unprobed port should have an empty state")
	}
}

func TestRunEmptyInput(t *testing.T) {
	res, stats := Run(context.Background(), nil, []uint16{80}, Config{})
	if len(res) != 0 || stats.ProbesPlanned != 0 || stats.Interrupted {
		t.Fatalf("got %v, %+v", res, stats)
	}
}

func TestRunCountsLocalErrors(t *testing.T) {
	d := &fakeDialer{fn: func(context.Context, string) error {
		return &net.OpError{Op: "dial", Err: os.NewSyscallError("socket", syscall.EMFILE)}
	}}
	res, stats := Run(context.Background(), loopback, []uint16{22, 80}, Config{Dialer: d})
	if stats.LocalErrors != 2 || stats.FirstLocalError == "" {
		t.Fatalf("stats = %+v; want 2 local errors", stats)
	}
	if res[0].Up || res[0].Ports[0].State != Filtered {
		t.Fatalf("got %+v", res[0])
	}
}
