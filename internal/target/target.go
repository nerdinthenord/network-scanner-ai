// Package target turns user-supplied target specifications into a bounded,
// scope-checked list of addresses.
//
// Scope enforcement lives here, before any packet is sent, so that every
// caller of the engine gets the same safety behaviour.
package target

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
)

// DefaultMaxHosts caps how many addresses a single invocation may expand to.
const DefaultMaxHosts = 4096

// Options controls expansion and scope enforcement.
type Options struct {
	// AllowPublic permits addresses outside private, loopback and link-local
	// space. It is off by default: scanning networks you do not own or have
	// written permission to test may be illegal.
	AllowPublic bool
	// MaxHosts is the upper bound on expanded addresses. Zero means
	// DefaultMaxHosts.
	MaxHosts int
}

// ErrOutOfScope is wrapped by errors returned for addresses that the scope
// policy refuses.
var ErrOutOfScope = errors.New("target out of scope")

// ErrTooManyHosts is wrapped when a specification expands past MaxHosts.
var ErrTooManyHosts = errors.New("too many hosts")

// Expand parses each spec (single address, CIDR prefix, or "first-last"
// range), applies the scope policy, and returns the de-duplicated addresses
// in the order given.
func Expand(specs []string, opt Options) ([]netip.Addr, error) {
	if len(specs) == 0 {
		return nil, errors.New("no targets given")
	}
	limit := opt.MaxHosts
	if limit <= 0 {
		limit = DefaultMaxHosts
	}

	seen := make(map[netip.Addr]struct{})
	var out []netip.Addr
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			return nil, errors.New("empty target")
		}
		first, last, err := parseSpec(spec)
		if err != nil {
			return nil, err
		}
		n := span(first, last)
		if !n.IsInt64() || n.Int64() > int64(limit-len(out)) {
			return nil, fmt.Errorf("%w: %q would exceed the limit of %d (raise it with --max-hosts)",
				ErrTooManyHosts, spec, limit)
		}
		for a := first; ; a = a.Next() {
			if err := checkScope(a, opt.AllowPublic); err != nil {
				return nil, fmt.Errorf("%q: %w", spec, err)
			}
			if _, dup := seen[a]; !dup {
				seen[a] = struct{}{}
				out = append(out, a)
			}
			if a == last {
				break
			}
		}
	}
	return out, nil
}

// parseSpec returns the inclusive first and last address a spec covers.
func parseSpec(spec string) (first, last netip.Addr, err error) {
	switch {
	case strings.Contains(spec, "/"):
		p, perr := netip.ParsePrefix(spec)
		if perr != nil {
			return first, last, fmt.Errorf("invalid CIDR %q: %v", spec, perr)
		}
		p = p.Masked()
		first, last = p.Addr(), lastAddr(p)
		// For IPv4 networks with usable host space, skip the network and
		// broadcast addresses.
		if p.Addr().Is4() && p.Bits() <= 30 {
			first, last = first.Next(), last.Prev()
		}
		return first, last, nil

	case strings.Contains(spec, "-"):
		lo, hi, _ := strings.Cut(spec, "-")
		first, err = parseAddr(lo)
		if err != nil {
			return first, last, err
		}
		last, err = parseAddr(hi)
		if err != nil {
			return first, last, err
		}
		if first.Is4() != last.Is4() {
			return first, last, fmt.Errorf("range %q mixes IPv4 and IPv6", spec)
		}
		if last.Less(first) {
			return first, last, fmt.Errorf("range %q ends before it starts", spec)
		}
		return first, last, nil

	default:
		first, err = parseAddr(spec)
		return first, first, err
	}
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return a, fmt.Errorf("invalid address %q (hostnames are not supported; use an IP, CIDR or range)", s)
	}
	if a.Zone() != "" {
		return a, fmt.Errorf("invalid address %q: zones are not supported", s)
	}
	return a.Unmap(), nil
}

// lastAddr returns the highest address inside a masked prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// span returns how many addresses lie in [first, last].
func span(first, last netip.Addr) *big.Int {
	lo := new(big.Int).SetBytes(first.AsSlice())
	hi := new(big.Int).SetBytes(last.AsSlice())
	return hi.Sub(hi, lo).Add(hi, big.NewInt(1))
}

func checkScope(a netip.Addr, allowPublic bool) error {
	if a.IsUnspecified() || a.IsMulticast() {
		return fmt.Errorf("%w: %s is not a scannable unicast address", ErrOutOfScope, a)
	}
	if a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("%w: %s is the broadcast address", ErrOutOfScope, a)
	}
	if allowPublic || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return nil
	}
	return fmt.Errorf("%w: %s is a public address; pass --allow-public only if you are authorized to scan it",
		ErrOutOfScope, a)
}
