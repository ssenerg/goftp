package server

import (
	"net/http"
	"strings"
	"time"
)

// notModified evaluates If-None-Match, falling back to If-Modified-Since
// (RFC 9110 section 13.2.2).
func notModified(ifNoneMatch, ifModifiedSince, etag string, modTime time.Time) bool {
	if ifNoneMatch != "" {
		return etagListMatch(ifNoneMatch, etag)
	}
	if ifModifiedSince == "" {
		return false
	}
	t, err := http.ParseTime(ifModifiedSince)
	return err == nil && !modTime.Truncate(time.Second).After(t)
}

// ifRangeMatch reports whether an If-Range validator allows a partial
// response. Entity tags need a strong match, dates an exact one.
func ifRangeMatch(ifRange, etag string, modTime time.Time) bool {
	if ifRange == "" {
		return true
	}
	if tag, rest := scanETag(ifRange); tag != "" {
		return strings.TrimSpace(rest) == "" && tag == etag && !strings.HasPrefix(tag, "W/")
	}
	t, err := http.ParseTime(ifRange)
	return err == nil && t.Equal(modTime.Truncate(time.Second))
}

// etagListMatch applies weak comparison to an If-None-Match list.
func etagListMatch(list, etag string) bool {
	for {
		list = strings.TrimLeft(list, " \t,")
		if list == "" {
			return false
		}
		if list[0] == '*' {
			return true
		}
		tag, rest := scanETag(list)
		if tag == "" {
			return false
		}
		if strings.TrimPrefix(tag, "W/") == strings.TrimPrefix(etag, "W/") {
			return true
		}
		list = rest
	}
}

// scanETag returns the leading entity-tag of s and the remaining text.
func scanETag(s string) (string, string) {
	s = strings.TrimLeft(s, " \t")
	start := 0
	if strings.HasPrefix(s, "W/") {
		start = 2
	}
	if len(s)-start < 2 || s[start] != '"' {
		return "", ""
	}
	for i := start + 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			return s[:i+1], s[i+1:]
		case c == 0x21 || (c >= 0x23 && c != 0x7f):
		default:
			return "", ""
		}
	}
	return "", ""
}
