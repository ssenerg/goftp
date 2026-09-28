package server

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseRange(t *testing.T) {
	const size = 100
	tests := []struct {
		header string
		want   []byteRange
		err    error
	}{
		{"bytes=0-9", []byteRange{{0, 10}}, nil},
		{"bytes=90-", []byteRange{{90, 10}}, nil},
		{"bytes=-10", []byteRange{{90, 10}}, nil},
		{"bytes=-1000", []byteRange{{0, 100}}, nil},
		{"bytes=95-1000", []byteRange{{95, 5}}, nil},
		{"BYTES = 0-0 , 99-99", []byteRange{{0, 1}, {99, 1}}, nil},
		{"bytes=,0-1,", []byteRange{{0, 2}}, nil},
		{"bytes=0-1,200-300", []byteRange{{0, 2}}, nil},

		{"bytes=100-", nil, errUnsatisfiable},
		{"bytes=100-200,300-", nil, errUnsatisfiable},
		{"bytes=-0", nil, errUnsatisfiable},

		// Ignored: unknown unit, malformed, too large in total.
		{"items=0-1", nil, nil},
		{"bytes", nil, nil},
		{"bytes=", nil, nil},
		{"bytes=,", nil, nil},
		{"bytes=5", nil, nil},
		{"bytes=-", nil, nil},
		{"bytes=9-5", nil, nil},
		{"bytes=a-b", nil, nil},
		{"bytes=+1-2", nil, nil},
		{"bytes=0x1-2", nil, nil},
		{"bytes=0-99999999999999999999", nil, nil},
		{"bytes=0-,0-", nil, nil},
		{"bytes=0-60,40-99", nil, nil},
		{"bytes=" + strings.Repeat("0-0,", maxRanges) + "0-0", nil, nil},
	}
	for _, tt := range tests {
		got, err := parseRange(tt.header, size)
		if !errors.Is(err, tt.err) || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseRange(%q) = %v, %v; want %v, %v", tt.header, got, err, tt.want, tt.err)
		}
	}
}

func TestContentRange(t *testing.T) {
	if got := (byteRange{start: 5, length: 10}).contentRange(100); got != "bytes 5-14/100" {
		t.Fatalf("got %q", got)
	}
}
