package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var fast = Config{Timeout: 2 * time.Second, BannerWait: 100 * time.Millisecond}

func targetOf(t *testing.T, addr net.Addr) Target {
	t.Helper()
	ap := netip.MustParseAddrPort(addr.String())
	return Target{Addr: ap.Addr(), Port: ap.Port()}
}

// serve runs handler for every connection accepted on a loopback listener.
func serve(t *testing.T, handler func(net.Conn)) Target {
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
			go func() { defer func() { _ = c.Close() }(); handler(c) }()
		}
	}()
	return targetOf(t, l.Addr())
}

func TestBanners(t *testing.T) {
	tests := []struct {
		banner, wantName, wantBanner string
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", "ssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"},
		{"220 ProFTPD Server (Debian) ready\r\n", "ftp", "220 ProFTPD Server (Debian) ready"},
		{"220 mail.example.test ESMTP Postfix\r\n", "smtp", "220 mail.example.test ESMTP Postfix"},
		{"+OK Dovecot ready.\r\n", "pop3", "+OK Dovecot ready."},
		{"* OK [CAPABILITY IMAP4rev1] ready\r\n", "imap", "* OK [CAPABILITY IMAP4rev1] ready"},
		{"RFB 003.008\n", "vnc", "RFB 003.008"},
		{"220 welcome\r\n", "", "220 welcome"},
		{"hello\x00\x1b[31m\xff world\nsecond line", "", "hello..[31m. world"},
	}
	for _, tc := range tests {
		tgt := serve(t, func(c net.Conn) { _, _ = c.Write([]byte(tc.banner)); time.Sleep(300 * time.Millisecond) })
		got := One(context.Background(), tgt, fast)
		if got.Name != tc.wantName || got.Banner != tc.wantBanner {
			t.Errorf("banner %q: got name %q banner %q", tc.banner, got.Name, got.Banner)
		}
	}
}

func TestBannerIsCapped(t *testing.T) {
	tgt := serve(t, func(c net.Conn) { _, _ = c.Write([]byte(strings.Repeat("A", 5000))) })
	if got := One(context.Background(), tgt, fast); len(got.Banner) != maxText {
		t.Fatalf("banner length %d, want %d", len(got.Banner), maxText)
	}
}

func TestHTTP(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.UserAgent()
		w.Header().Set("Server", "TestServer/1.2")
		_, _ = fmt.Fprint(w, "<html><head><TITLE>\n  Router   Admin\n</TITLE></head></html>")
	}))
	defer srv.Close()

	cfg := fast
	cfg.UserAgent = "protolan/test"
	got := One(context.Background(), targetOf(t, srv.Listener.Addr()), cfg)
	if got.Name != "http" || got.HTTP == nil || got.TLS != nil {
		t.Fatalf("got %+v", got)
	}
	if got.HTTP.Status != 200 || got.HTTP.Server != "TestServer/1.2" || got.HTTP.Title != "Router Admin" {
		t.Fatalf("http = %+v", got.HTTP)
	}
	if gotUA != "protolan/test" {
		t.Fatalf("user agent = %q", gotUA)
	}
}

func TestHTTPSOnUnconventionalPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "SecureThing")
		_, _ = fmt.Fprint(w, "<title>Login</title>")
	}))
	defer srv.Close()
	leaf := srv.Certificate()

	cfg := fast
	cfg.Now = func() time.Time { return leaf.NotAfter.Add(-time.Hour) }
	got := One(context.Background(), targetOf(t, srv.Listener.Addr()), cfg)
	if got.Name != "https" || got.TLS == nil || got.HTTP == nil {
		t.Fatalf("got %+v", got)
	}
	if got.HTTP.Server != "SecureThing" || got.HTTP.Title != "Login" {
		t.Errorf("http = %+v", got.HTTP)
	}
	tl := got.TLS
	if !strings.HasPrefix(tl.Version, "TLS 1.") || len(tl.SHA256) != 64 || tl.Expired {
		t.Errorf("tls = %+v", tl)
	}
	if !tl.NotAfter.Equal(leaf.NotAfter) || tl.Subject == "" {
		t.Errorf("certificate fields wrong: %+v", tl)
	}

	cfg.Now = func() time.Time { return leaf.NotAfter.Add(time.Hour) }
	if got := One(context.Background(), targetOf(t, srv.Listener.Addr()), cfg); got.TLS == nil || !got.TLS.Expired {
		t.Fatalf("certificate past NotAfter must be reported expired: %+v", got.TLS)
	}
}

func TestSilentServiceYieldsNothing(t *testing.T) {
	tgt := serve(t, func(c net.Conn) { _, _ = c.Read(make([]byte, 4096)); time.Sleep(400 * time.Millisecond) })
	cfg := Config{Timeout: 300 * time.Millisecond, BannerWait: 50 * time.Millisecond}
	if got := One(context.Background(), tgt, cfg); !got.IsZero() {
		t.Fatalf("got %+v, want nothing", got)
	}
}

func TestClosedPortYieldsNothing(t *testing.T) {
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	tgt := targetOf(t, l.Addr())
	_ = l.Close()
	if got := One(context.Background(), tgt, fast); !got.IsZero() {
		t.Fatalf("got %+v", got)
	}
}

// pipeDialer hands out one end of an in-memory pipe and gives the other end
// to the test, whatever address is dialled.
type pipeDialer struct{ server chan net.Conn }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c, s := net.Pipe()
	d.server <- s
	return c, nil
}

func TestPrintPortsNeverReceivePayload(t *testing.T) {
	for _, port := range []uint16{515, 9100, 9107} {
		d := pipeDialer{server: make(chan net.Conn, 4)}
		wrote := make(chan int, 1)
		go func() {
			s := <-d.server
			_ = s.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _ := s.Read(make([]byte, 64))
			wrote <- n
		}()
		cfg := Config{Timeout: 200 * time.Millisecond, BannerWait: 50 * time.Millisecond, Dialer: d}
		got := One(context.Background(), Target{Addr: netip.MustParseAddr("10.0.0.9"), Port: port}, cfg)
		if n := <-wrote; n != 0 || !got.IsZero() {
			t.Errorf("port %d: scanner wrote %d bytes to a no-payload port (result %+v)", port, n, got)
		}
	}
}

func TestOrdinaryPortDoesReceiveHTTPRequest(t *testing.T) {
	d := pipeDialer{server: make(chan net.Conn, 4)}
	got := make(chan string, 1)
	go func() {
		s := <-d.server
		buf := make([]byte, 256)
		_ = s.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := s.Read(buf)
		got <- string(buf[:n])
		_ = s.Close()
	}()
	cfg := Config{Timeout: 200 * time.Millisecond, BannerWait: 50 * time.Millisecond, Dialer: d}
	go One(context.Background(), Target{Addr: netip.MustParseAddr("fd00::9"), Port: 8080}, cfg)
	req := <-got
	if !strings.HasPrefix(req, "GET / HTTP/1.0\r\nHost: [fd00::9]\r\n") {
		t.Fatalf("unexpected request: %q", req)
	}
}

func TestAll(t *testing.T) {
	ssh := serve(t, func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-dropbear_2022.83\r\n"))
		time.Sleep(200 * time.Millisecond)
	})
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "ok") }))
	defer web.Close()
	webT := targetOf(t, web.Listener.Addr())

	got := All(context.Background(), []Target{ssh, webT}, fast)
	if len(got) != 2 || got[ssh].Name != "ssh" || got[webT].Name != "http" {
		t.Fatalf("got %+v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := All(ctx, []Target{ssh, webT}, fast); len(got) != 0 {
		t.Fatalf("cancelled run probed %d targets", len(got))
	}
	if got := All(context.Background(), nil, fast); len(got) != 0 {
		t.Fatal("empty input should yield empty output")
	}
}
