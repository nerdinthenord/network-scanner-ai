// Package probe learns what is listening on an open TCP port.
//
// It first listens for a banner the service volunteers. Only if the service
// stays silent does it send anything: a minimal HTTP request, and failing
// that a TLS handshake. Ports where an unsolicited payload is known to cause
// side effects (raw printing) never receive one.
package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Service is what was learned about one open port. The zero value means
// nothing could be determined.
type Service struct {
	// Name is the protocol when recognised: ssh, http, https, tls, ftp,
	// smtp, pop3, imap or vnc.
	Name string `json:"name,omitempty"`
	// Banner is the first line the service sent, reduced to printable ASCII.
	Banner string `json:"banner,omitempty"`
	HTTP   *HTTP  `json:"http,omitempty"`
	TLS    *TLS   `json:"tls,omitempty"`
}

// IsZero reports whether nothing was learned.
func (s Service) IsZero() bool {
	return s.Name == "" && s.Banner == "" && s.HTTP == nil && s.TLS == nil
}

// HTTP describes the response to "GET /".
type HTTP struct {
	Status int    `json:"status"`
	Server string `json:"server,omitempty"`
	Title  string `json:"title,omitempty"`
}

// TLS describes the handshake and the leaf certificate presented.
type TLS struct {
	Version    string    `json:"version"`
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	SANs       []string  `json:"sans,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	Expired    bool      `json:"expired"`
	SHA256     string    `json:"sha256"`
}

// Target is one open port to examine.
type Target struct {
	Addr netip.Addr
	Port uint16
}

// Dialer matches scan.Dialer; it is redeclared to keep this package
// independent of the scan engine.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Defaults for zero Config fields.
const (
	DefaultTimeout     = 3 * time.Second
	DefaultBannerWait  = 600 * time.Millisecond
	DefaultConcurrency = 32
)

// Config tunes probing.
type Config struct {
	// Timeout bounds each connection, handshake and response read.
	Timeout time.Duration
	// BannerWait is how long to listen before concluding the service will
	// not speak first.
	BannerWait  time.Duration
	Concurrency int
	Dialer      Dialer
	// UserAgent identifies the scanner in HTTP requests so operators can
	// recognise its traffic in their logs.
	UserAgent string
	// Now is the clock used to judge certificate expiry.
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.BannerWait <= 0 {
		c.BannerWait = DefaultBannerWait
	}
	if c.Concurrency <= 0 {
		c.Concurrency = DefaultConcurrency
	}
	if c.Dialer == nil {
		c.Dialer = &net.Dialer{}
	}
	if c.UserAgent == "" {
		c.UserAgent = "protolan"
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

const (
	maxBanner   = 512
	maxResponse = 16 << 10
	maxText     = 200 // cap on any reported string
	maxSANs     = 10
)

// tlsFirst lists ports where TLS is the convention, so the handshake is
// tried before anything else.
func tlsFirst(port uint16) bool {
	switch port {
	case 443, 465, 636, 853, 993, 995, 2376, 5986, 6443, 8443, 8883, 9443, 10250:
		return true
	}
	return false
}

// noPayload lists ports that must never be sent unsolicited data. Raw print
// services (9100-9107) print whatever arrives, and LPD (515) can queue jobs.
func noPayload(port uint16) bool {
	return port == 515 || (port >= 9100 && port <= 9107)
}

// All probes every target with bounded concurrency. Targets not reached
// before ctx ends are absent from the result.
func All(ctx context.Context, targets []Target, cfg Config) map[Target]Service {
	cfg = cfg.withDefaults()
	out := make(map[Target]Service, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan Target)

	for range min(cfg.Concurrency, len(targets)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					continue
				}
				s := One(ctx, t, cfg)
				mu.Lock()
				out[t] = s
				mu.Unlock()
			}
		}()
	}
feed:
	for _, t := range targets {
		select {
		case jobs <- t:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// One probes a single open port.
func One(ctx context.Context, t Target, cfg Config) Service {
	cfg = cfg.withDefaults()
	if tlsFirst(t.Port) {
		if s, ok := viaTLS(ctx, t, cfg); ok {
			return s
		}
	}
	s, tryTLS := viaPlain(ctx, t, cfg)
	if tryTLS && !tlsFirst(t.Port) {
		if ts, ok := viaTLS(ctx, t, cfg); ok {
			return ts
		}
	}
	return s
}

func dial(ctx context.Context, t Target, cfg Config) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	return cfg.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.Addr.String(), strconv.Itoa(int(t.Port))))
}

// viaPlain talks cleartext. tryTLS reports whether the outcome suggests the
// port actually expects TLS.
func viaPlain(ctx context.Context, t Target, cfg Config) (s Service, tryTLS bool) {
	conn, err := dial(ctx, t, cfg)
	if err != nil {
		return Service{}, false
	}
	defer func() { _ = conn.Close() }()

	if banner := read(conn, cfg.BannerWait, 150*time.Millisecond, maxBanner); len(banner) > 0 {
		return fromBanner(banner), false
	}
	if noPayload(t.Port) {
		return Service{}, false
	}

	resp, ok := httpGet(conn, t, cfg)
	if !ok {
		return Service{}, true
	}
	if h, isHTTP := parseHTTP(resp); isHTTP {
		// Servers answer 400 when sent cleartext HTTP on a TLS port.
		return Service{Name: "http", HTTP: h}, h.Status == http.StatusBadRequest
	}
	return Service{Banner: clean(resp)}, true
}

func viaTLS(ctx context.Context, t Target, cfg Config) (Service, bool) {
	raw, err := dial(ctx, t, cfg)
	if err != nil {
		return Service{}, false
	}
	defer func() { _ = raw.Close() }()

	// Verification is deliberately off and legacy versions are accepted:
	// the goal is to record what the service presents, including
	// self-signed, expired and outdated configurations. Nothing sensitive
	// is sent over this connection and its contents are not trusted.
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // inventory, not trust; see above
		MinVersion:         tls.VersionTLS10,
	})
	hctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		return Service{}, false
	}
	state := conn.ConnectionState()
	s := Service{Name: "tls", TLS: &TLS{Version: tls.VersionName(state.Version)}}
	if len(state.PeerCertificates) > 0 {
		fillCert(s.TLS, state.PeerCertificates[0], cfg.Now())
	}

	if noPayload(t.Port) {
		return s, true
	}
	if resp, ok := httpGet(conn, t, cfg); ok {
		if h, isHTTP := parseHTTP(resp); isHTTP {
			s.Name, s.HTTP = "https", h
		}
	}
	return s, true
}

func fillCert(info *TLS, cert *x509.Certificate, now time.Time) {
	info.Subject = clean([]byte(nameOf(cert.Subject.CommonName, cert.Subject.Organization)))
	info.Issuer = clean([]byte(nameOf(cert.Issuer.CommonName, cert.Issuer.Organization)))
	for _, n := range cert.DNSNames {
		if len(info.SANs) == maxSANs {
			break
		}
		info.SANs = append(info.SANs, clean([]byte(n)))
	}
	info.NotBefore, info.NotAfter = cert.NotBefore.UTC(), cert.NotAfter.UTC()
	info.SelfSigned = bytes.Equal(cert.RawIssuer, cert.RawSubject)
	info.Expired = now.After(cert.NotAfter)
	sum := sha256.Sum256(cert.Raw)
	info.SHA256 = hex.EncodeToString(sum[:])
}

func nameOf(cn string, org []string) string {
	if cn != "" || len(org) == 0 {
		return cn
	}
	return org[0]
}

// httpGet sends a minimal request and returns whatever came back.
func httpGet(conn net.Conn, t Target, cfg Config) ([]byte, bool) {
	host := t.Addr.String()
	if t.Addr.Is6() {
		host = "[" + host + "]"
	}
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n", host, cfg.UserAgent)
	_ = conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, false
	}
	resp := read(conn, cfg.Timeout, 300*time.Millisecond, maxResponse)
	return resp, len(resp) > 0
}

// read collects up to max bytes. It waits up to first for data to begin and
// up to rest between later chunks.
func read(conn net.Conn, first, rest time.Duration, max int) []byte {
	var buf []byte
	tmp := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(first))
	for len(buf) < max {
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(rest))
	}
	if len(buf) > max {
		buf = buf[:max]
	}
	return buf
}

func fromBanner(b []byte) Service {
	if h, ok := parseHTTP(b); ok {
		return Service{Name: "http", HTTP: h}
	}
	s := Service{Banner: clean(b)}
	upper := strings.ToUpper(s.Banner)
	switch {
	case strings.HasPrefix(upper, "SSH-"):
		s.Name = "ssh"
	case strings.HasPrefix(upper, "220") && strings.Contains(upper, "FTP"):
		s.Name = "ftp"
	case strings.HasPrefix(upper, "220") && strings.Contains(upper, "SMTP"):
		s.Name = "smtp"
	case strings.HasPrefix(upper, "+OK"):
		s.Name = "pop3"
	case strings.HasPrefix(upper, "* OK"):
		s.Name = "imap"
	case strings.HasPrefix(upper, "RFB "):
		s.Name = "vnc"
	}
	return s
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func parseHTTP(data []byte) (*HTTP, bool) {
	if !bytes.HasPrefix(data, []byte("HTTP/")) {
		return nil, false
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	h := &HTTP{Status: resp.StatusCode, Server: clean([]byte(resp.Header.Get("Server")))}
	// The body may be cut short; use whatever arrived.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if m := titleRE.FindSubmatch(body); m != nil {
		h.Title = clean(bytes.Join(bytes.Fields(m[1]), []byte(" ")))
	}
	return h, true
}

// clean returns the first line of b as printable ASCII, capped in length.
// Remote services control this text, so it is never passed through raw.
func clean(b []byte) string {
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		b = b[:i]
	}
	var sb strings.Builder
	for _, c := range b {
		if sb.Len() == maxText {
			break
		}
		if c < 0x20 || c > 0x7e {
			c = '.'
		}
		sb.WriteByte(c)
	}
	return strings.TrimSpace(sb.String())
}
