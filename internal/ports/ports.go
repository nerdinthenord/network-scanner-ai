// Package ports parses port specifications.
package ports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Common is Protolan's own short list of TCP ports that most often matter in
// an exposure review. It is maintained by hand in this repository and is not
// derived from any third-party service database.
var Common = []uint16{
	21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 179, 389, 443, 445,
	465, 515, 548, 554, 587, 631, 636, 873, 993, 995, 1433, 1521, 1883, 2049,
	2375, 2379, 3000, 3306, 3389, 5000, 5432, 5672, 5900, 5985, 6379, 6443,
	7000, 8000, 8008, 8009, 8080, 8443, 8883, 9000, 9090, 9092, 9100, 9200,
	10250, 11211, 27017, 62078,
}

// Parse accepts "common", "all", or a comma-separated list of ports and
// inclusive ranges such as "22,80,8000-8100". The result is sorted and
// de-duplicated.
func Parse(spec string) ([]uint16, error) {
	spec = strings.TrimSpace(spec)
	switch strings.ToLower(spec) {
	case "":
		return nil, fmt.Errorf("empty port specification")
	case "common":
		out := make([]uint16, len(Common))
		copy(out, Common)
		return out, nil
	case "all":
		spec = "1-65535"
	}

	set := make(map[uint16]struct{})
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty entry in port specification %q", spec)
		}
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		last := first
		if isRange {
			if last, err = parsePort(hi); err != nil {
				return nil, err
			}
			if last < first {
				return nil, fmt.Errorf("port range %q ends before it starts", part)
			}
		}
		for p := int(first); p <= int(last); p++ {
			set[uint16(p)] = struct{}{}
		}
	}

	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q (expected 1-65535)", s)
	}
	return uint16(n), nil
}
