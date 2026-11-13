package ports

import (
	"slices"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		spec string
		want []uint16
	}{
		{"80", []uint16{80}},
		{"443, 22,80", []uint16{22, 80, 443}},
		{"8000-8002", []uint16{8000, 8001, 8002}},
		{"22,20-23,22", []uint16{20, 21, 22, 23}},
		{"65535", []uint16{65535}},
	}
	for _, tc := range tests {
		got, err := Parse(tc.spec)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("Parse(%q) = %v, %v; want %v", tc.spec, got, err, tc.want)
		}
	}
}

func TestParseKeywords(t *testing.T) {
	all, err := Parse("ALL")
	if err != nil || len(all) != 65535 || all[0] != 1 || all[65534] != 65535 {
		t.Fatalf("all: len %d, err %v", len(all), err)
	}
	common, err := Parse("common")
	if err != nil || !slices.Equal(common, Common) {
		t.Fatalf("common: %v, %v", common, err)
	}
	common[0] = 9 // the caller's copy must not alias the package list
	if Common[0] == 9 {
		t.Fatal("Parse returned the shared Common slice")
	}
}

func TestCommonIsSortedAndUnique(t *testing.T) {
	if !slices.IsSorted(Common) || len(slices.Compact(slices.Clone(Common))) != len(Common) {
		t.Fatal("Common must be sorted with no duplicates")
	}
}

func TestParseRejects(t *testing.T) {
	for _, spec := range []string{"", "0", "65536", "-1", "abc", "80,", "80,,443", "90-80", "80-", "1-70000"} {
		if got, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q) = %v; want error", spec, got)
		}
	}
}
