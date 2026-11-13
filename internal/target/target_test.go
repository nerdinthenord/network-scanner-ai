package target

import (
	"errors"
	"net/netip"
	"testing"
)

func addrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestExpand(t *testing.T) {
	tests := []struct {
		name  string
		specs []string
		want  []string
	}{
		{"single", []string{"192.168.1.5"}, []string{"192.168.1.5"}},
		{"cidr skips network and broadcast", []string{"10.0.0.0/30"}, []string{"10.0.0.1", "10.0.0.2"}},
		{"cidr host bits are masked", []string{"10.0.0.2/30"}, []string{"10.0.0.1", "10.0.0.2"}},
		{"slash 31 keeps both", []string{"10.0.0.0/31"}, []string{"10.0.0.0", "10.0.0.1"}},
		{"slash 32", []string{"10.0.0.7/32"}, []string{"10.0.0.7"}},
		{"range", []string{"172.16.0.9-172.16.0.11"}, []string{"172.16.0.9", "172.16.0.10", "172.16.0.11"}},
		{"dedupe keeps first position", []string{"10.0.0.2", "10.0.0.1-10.0.0.2"}, []string{"10.0.0.2", "10.0.0.1"}},
		{"loopback", []string{"127.0.0.1"}, []string{"127.0.0.1"}},
		{"ipv6 unique local", []string{"fd00::1"}, []string{"fd00::1"}},
		{"ipv4-mapped is unmapped", []string{"::ffff:10.0.0.1"}, []string{"10.0.0.1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Expand(tc.specs, Options{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := addrs(t, tc.want...)
			if len(got) != len(want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("got %v, want %v", got, want)
				}
			}
		})
	}
}

func TestExpandRejects(t *testing.T) {
	tests := []struct {
		name  string
		specs []string
		opt   Options
		is    error // nil means any error
	}{
		{"no targets", nil, Options{}, nil},
		{"empty", []string{" "}, Options{}, nil},
		{"hostname", []string{"example.com"}, Options{}, nil},
		{"bad cidr", []string{"10.0.0.0/33"}, Options{}, nil},
		{"reversed range", []string{"10.0.0.9-10.0.0.1"}, Options{}, nil},
		{"mixed family range", []string{"10.0.0.1-fd00::1"}, Options{}, nil},
		{"zone", []string{"fe80::1%eth0"}, Options{}, nil},
		{"public address", []string{"8.8.8.8"}, Options{}, ErrOutOfScope},
		{"public inside range", []string{"192.168.255.254-192.169.0.1"}, Options{}, ErrOutOfScope},
		{"multicast even when public allowed", []string{"224.0.0.1"}, Options{AllowPublic: true}, ErrOutOfScope},
		{"unspecified", []string{"0.0.0.0"}, Options{AllowPublic: true}, ErrOutOfScope},
		{"broadcast", []string{"255.255.255.255"}, Options{AllowPublic: true}, ErrOutOfScope},
		{"over default limit", []string{"10.0.0.0/8"}, Options{}, ErrTooManyHosts},
		{"over custom limit", []string{"10.0.0.0/29"}, Options{MaxHosts: 5}, ErrTooManyHosts},
		{"limit is cumulative", []string{"10.0.0.0/30", "10.0.1.0/30"}, Options{MaxHosts: 3}, ErrTooManyHosts},
		{"huge ipv6 prefix", []string{"fd00::/8"}, Options{}, ErrTooManyHosts},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Expand(tc.specs, tc.opt)
			if err == nil {
				t.Fatalf("expected an error, got %v", got)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("error %v does not wrap %v", err, tc.is)
			}
		})
	}
}

func TestExpandAllowPublic(t *testing.T) {
	got, err := Expand([]string{"8.8.8.8"}, Options{AllowPublic: true})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestExpandAtLimit(t *testing.T) {
	got, err := Expand([]string{"10.0.0.0/29"}, Options{MaxHosts: 6})
	if err != nil || len(got) != 6 {
		t.Fatalf("got %d addrs, err %v; want 6", len(got), err)
	}
}
