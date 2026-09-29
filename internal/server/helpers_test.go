package server

import (
	"net/http"
	"testing"
	"time"
)

func TestNotModified(t *testing.T) {
	const etag = `"abc-1"`
	mod := time.Date(2024, 5, 1, 10, 0, 0, 500, time.UTC)
	tests := []struct {
		inm, ims string
		want     bool
	}{
		{"", "", false},
		{etag, "", true},
		{`W/"abc-1"`, "", true},
		{`"x", "abc-1"`, "", true},
		{`"x",W/"abc-1"`, "", true},
		{"*", "", true},
		{`"other"`, "", false},
		{`garbage`, "", false},
		{`"other"`, mod.Add(time.Hour).Format(http.TimeFormat), false},
		{"", mod.Format(http.TimeFormat), true},
		{"", mod.Add(time.Hour).Format(http.TimeFormat), true},
		{"", mod.Add(-time.Hour).Format(http.TimeFormat), false},
		{"", "not a date", false},
	}
	for _, tt := range tests {
		if got := notModified(tt.inm, tt.ims, etag, mod); got != tt.want {
			t.Errorf("notModified(%q, %q) = %v, want %v", tt.inm, tt.ims, got, tt.want)
		}
	}
}

func TestIfRangeMatch(t *testing.T) {
	const etag = `"abc-1"`
	mod := time.Date(2024, 5, 1, 10, 0, 0, 500, time.UTC)
	tests := []struct {
		ifRange string
		want    bool
	}{
		{"", true},
		{etag, true},
		{`W/"abc-1"`, false},
		{`"abc-2"`, false},
		{`"abc-1", "x"`, false},
		{mod.Format(http.TimeFormat), true},
		{mod.Add(time.Second).Format(http.TimeFormat), false},
		{"junk", false},
	}
	for _, tt := range tests {
		if got := ifRangeMatch(tt.ifRange, etag, mod); got != tt.want {
			t.Errorf("ifRangeMatch(%q) = %v, want %v", tt.ifRange, got, tt.want)
		}
	}
}

func TestCleanPath(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantDir bool
		bad     bool
	}{
		{"/", "/", true, false},
		{"", "/", false, false},
		{"/a/b/", "/a/b", true, false},
		{"//a//b", "/a/b", false, false},
		{"/a/./b/../c", "/a/c", false, false},
		{"/../../etc/passwd", "/etc/passwd", false, false},
		{"/%2e%2e/%2e%2e/etc", "/etc", false, false},
		{"/a%2f..%2f..%2fb", "/b", false, false},
		{"/a%20b", "/a b", false, false},
		{"/a+b", "/a+b", false, false},
		{"/%00", "", false, true},
		{"/%zz", "", false, true},
	}
	for _, tt := range tests {
		got, dir, err := cleanPath(tt.raw)
		if (err != nil) != tt.bad || got != tt.want || dir != tt.wantDir {
			t.Errorf("cleanPath(%q) = %q, %v, %v", tt.raw, got, dir, err)
		}
	}
}

func TestEscapePath(t *testing.T) {
	tests := map[string]string{
		"/a b/c.txt":     "/a%20b/c.txt",
		"/x#y?z%.txt":    "/x%23y%3Fz%25.txt",
		"/ü.txt":         "/%C3%BC.txt",
		`/"q'<x>`:        "/%22q%27%3Cx%3E",
		"/a:b;c=d@e+f,g": "/a:b;c=d@e+f,g",
	}
	for in, want := range tests {
		if got := escapePath(in); got != want {
			t.Errorf("escapePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientKey(t *testing.T) {
	tests := map[string]string{
		"203.0.113.7":             "203.0.113.7",
		"::ffff:203.0.113.7":      "203.0.113.7",
		"2001:db8:1:2:3:4:5:6":    "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1234": "2001:db8:1:2::/64",
		"not-an-ip":               "not-an-ip",
	}
	for in, want := range tests {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatSize(t *testing.T) {
	tests := map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 30: "5.0 GiB"}
	for in, want := range tests {
		if got := formatSize(in); got != want {
			t.Errorf("formatSize(%d) = %q, want %q", in, got, want)
		}
	}
}
