package server

import (
	"errors"
	"strconv"
	"strings"
)

// maxRanges caps the range-specs accepted in one Range header.
const maxRanges = 64

var errUnsatisfiable = errors.New("range not satisfiable")

type byteRange struct {
	start, length int64
}

func (r byteRange) contentRange(size int64) string {
	return "bytes " + strconv.FormatInt(r.start, 10) + "-" +
		strconv.FormatInt(r.start+r.length-1, 10) + "/" + strconv.FormatInt(size, 10)
}

// parseRange parses a Range header (RFC 9110 section 14.1) for a
// representation of the given size (> 0). It returns nil ranges and a nil
// error when the header must be ignored (unknown unit, bad syntax, too many
// ranges or more bytes than the file holds), and errUnsatisfiable when no
// range overlaps the file.
func parseRange(header string, size int64) ([]byteRange, error) {
	unit, set, ok := strings.Cut(header, "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(unit), "bytes") {
		return nil, nil
	}

	var (
		ranges []byteRange
		specs  int
		total  int64
	)
	for _, spec := range strings.Split(set, ",") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		if specs++; specs > maxRanges {
			return nil, nil
		}
		first, last, ok := strings.Cut(spec, "-")
		if !ok {
			return nil, nil
		}
		first, last = strings.TrimSpace(first), strings.TrimSpace(last)

		var r byteRange
		if first == "" {
			n, ok := parseDigits(last)
			if !ok {
				return nil, nil
			}
			if n == 0 {
				continue
			}
			n = min(n, size)
			r = byteRange{start: size - n, length: n}
		} else {
			start, ok := parseDigits(first)
			if !ok {
				return nil, nil
			}
			end := size - 1
			if last != "" {
				e, ok := parseDigits(last)
				if !ok || e < start {
					return nil, nil
				}
				end = min(e, size-1)
			}
			if start >= size {
				continue
			}
			r = byteRange{start: start, length: end - start + 1}
		}

		// Overlapping ranges could multiply the response size.
		if r.length > size-total {
			return nil, nil
		}
		total += r.length
		ranges = append(ranges, r)
	}

	if specs == 0 {
		return nil, nil
	}
	if len(ranges) == 0 {
		return nil, errUnsatisfiable
	}
	return ranges, nil
}

func parseDigits(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}
