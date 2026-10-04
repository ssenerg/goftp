package server

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"goftp/internal/auth"
	"goftp/internal/config"
)

// testJPEG encodes a w×h JPEG, with an EXIF orientation if o > 0.
func testJPEG(t *testing.T, w, h, o int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{uint8(x * 255 / w), uint8(y * 255 / h), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if o == 0 {
		return data
	}
	return append(append(append([]byte{}, data[:2]...), exifSegment(binary.BigEndian, o)...), data[2:]...)
}

// exifSegment is an APP1 segment whose IFD0 holds an orientation.
func exifSegment(order binary.ByteOrder, o int) []byte {
	tiff := make([]byte, 8+2+12+4)
	if order == binary.LittleEndian {
		copy(tiff, "II")
	} else {
		copy(tiff, "MM")
	}
	order.PutUint16(tiff[2:], 42)
	order.PutUint32(tiff[4:], 8)
	order.PutUint16(tiff[8:], 1)
	order.PutUint16(tiff[10:], 0x0112)
	order.PutUint16(tiff[12:], 3)
	order.PutUint32(tiff[14:], 1)
	order.PutUint16(tiff[18:], uint16(o))
	payload := append([]byte("Exif\x00\x00"), tiff...)
	seg := []byte{0xFF, 0xE1, 0, 0}
	binary.BigEndian.PutUint16(seg[2:], uint16(len(payload)+2))
	return append(seg, payload...)
}

func testPNG(t *testing.T, w, h int, alpha bool) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			a := uint8(255)
			if alpha && x < w/2 {
				a = 0
			}
			img.Set(x, y, color.NRGBA{200, 50, 50, a})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestInlineType(t *testing.T) {
	pdf := "%PDF-1.4\n1 0 obj\n"
	for _, c := range []struct {
		name, head, ctype, kind string
	}{
		{"a.jpg", string(testJPEG(t, 4, 4, 0)), "image/jpeg", "image"},
		{"a.png", string(testPNG(t, 2, 2, false)), "image/png", "image"},
		{"a.gif", "GIF89a....", "image/gif", "image"},
		{"a.webp", "RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp", "image"},
		{"a.avif", "\x00\x00\x00\x1cftypavif\x00\x00\x00\x00", "image/avif", "image"},
		{"a.mp4", "\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom", "video/mp4", "video"},
		{"a.mp4", "\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2", "video/mp4", "video"},
		{"a.mov", "\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00qt  ", "video/quicktime", "video"},
		{"a.m4a", "\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00M4A mp42", "audio/mp4", "audio"},
		{"song", "\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00M4A isom", "audio/mp4", "audio"},
		{"film", "\x00\x00\x00\x18ftypM4V \x00\x00\x00\x00M4V isom", "video/mp4", "video"},
		{"a.webm", "\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\xf7\x81\x01\x42\xf2\x81\x04\x42\xf3\x81\x08\x42\x82\x84webm", "video/webm", "video"},
		{"a.mp3", "ID3\x04\x00", "audio/mpeg", "audio"},
		{"a.mp3", "\xff\xfb\x90\x64", "audio/mpeg", "audio"},
		{"a.bin", "\xff\xfb\x90\x64", "", ""},
		{"a.aac", "\xff\xf1\x50\x80", "audio/aac", "audio"},
		{"a.flac", "fLaC\x00\x00\x00\x22", "audio/flac", "audio"},
		{"a.wav", "RIFF\x00\x00\x00\x00WAVEfmt ", "audio/wav", "audio"},
		{"a.ogg", "OggS\x00\x02", "audio/ogg", "audio"},
		{"a.ogv", "OggS\x00\x02", "video/ogg", "video"},
		{"a.pdf", pdf, "application/pdf", "pdf"},
		{"anything", pdf, "application/pdf", "pdf"},
		// Never what could hold a script, whatever the name says.
		{"a.svg", `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`, "", ""},
		{"a.jpg", "<!DOCTYPE html><html><script>alert(1)</script>", "", ""},
		{"a.png", `<?xml version="1.0"?><svg/>`, "", ""},
		{"a.txt", "plain text", "", ""},
		{"empty.jpg", "", "", ""},
	} {
		ctype, kind := inlineType(strings.NewReader(c.head), c.name)
		if ctype != c.ctype || kind != c.kind {
			t.Errorf("inlineType(%s, %.12q) = %q, %q; want %q, %q", c.name, c.head, ctype, kind, c.ctype, c.kind)
		}
	}
}

// jpegFrame is a JPEG made of a frame header (marker 0xC0 to 0xC2) with
// components sampled as hv says, and an empty start of scan.
func jpegFrame(marker byte, w, h int, hv ...byte) []byte {
	seg := []byte{0xFF, marker, 0, 0, 8, byte(h >> 8), byte(h), byte(w >> 8), byte(w), byte(len(hv))}
	for i, f := range hv {
		seg = append(seg, byte(i+1), f, 0)
	}
	binary.BigEndian.PutUint16(seg[2:], uint16(len(seg)-2))
	return append(append([]byte{0xFF, 0xD8}, seg...), 0xFF, 0xDA, 0x00, 0x02)
}

func TestReadJPEGHeader(t *testing.T) {
	read := func(data []byte) (jpegHeader, error) { return readJPEGHeader(bytes.NewReader(data)) }
	exif := func(order binary.ByteOrder, o int) []byte {
		return append(append([]byte{0xFF, 0xD8}, exifSegment(order, o)...), testJPEG(t, 4, 4, 0)[2:]...)
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for o := 1; o <= 8; o++ {
			if h, err := read(exif(order, o)); err != nil || h.orientation != o {
				t.Errorf("%v %d: got %d, %v", order, o, h.orientation, err)
			}
		}
	}
	for name, data := range map[string][]byte{
		"no EXIF":    testJPEG(t, 4, 4, 0),
		"bad value":  exif(binary.BigEndian, 9),
		"other APP1": append([]byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, 'h', 't', 't', 'p', ':', '/'}, testJPEG(t, 4, 4, 0)[2:]...),
	} {
		if h, err := read(data); err != nil || h.orientation != 1 {
			t.Errorf("%s: got %d, %v", name, h.orientation, err)
		}
	}
	// The first EXIF segment counts.
	twice := append(exif(binary.BigEndian, 6)[:2+len(exifSegment(binary.BigEndian, 6))], exif(binary.BigEndian, 3)[2:]...)
	if h, _ := read(twice); h.orientation != 6 {
		t.Errorf("two EXIF segments: got %d", h.orientation)
	}

	// The memory decoding takes: planes of 8×8 blocks per sampling factor,
	// as many as there are components, plus the coefficients of
	// progressive JPEGs.
	for _, c := range []struct {
		name string
		data []byte
		cost int64
	}{
		{"Go's own", testJPEG(t, 800, 600, 0), 3 * 800 * 608},
		{"4:2:0", jpegFrame(0xC0, 8000, 6000, 0x22, 0x11, 0x11), 3 * 8000 * 6000},
		{"extended", jpegFrame(0xC1, 8000, 6000, 0x22, 0x11, 0x11), 3 * 8000 * 6000},
		{"progressive 4:2:0", jpegFrame(0xC2, 8000, 6000, 0x22, 0x11, 0x11), 3*8000*6000 + 500*375*(4+1+1)*256},
		{"progressive 4:4:4", jpegFrame(0xC2, 100, 100, 0x11, 0x11, 0x11), 3*104*104 + 13*13*3*256},
		{"gray, whatever its sampling", jpegFrame(0xC0, 100, 100, 0x22), 104 * 104},
		{"CMYK", jpegFrame(0xC0, 16, 16, 0x11, 0x11, 0x11, 0x11), 4 * 16 * 16},
		{"fill bytes", append([]byte{0xFF, 0xD8, 0xFF}, jpegFrame(0xC0, 8, 8, 0x11)[2:]...), 64},
		{"stray restart marker", append([]byte{0xFF, 0xD8, 0xFF, 0xD0}, jpegFrame(0xC0, 8, 8, 0x11)[2:]...), 64},
	} {
		if h, err := read(c.data); err != nil || h.cost != c.cost {
			t.Errorf("%s: cost %d, %v; want %d", c.name, h.cost, err, c.cost)
		}
	}

	for name, data := range map[string][]byte{
		"not a JPEG":      []byte("hello"),
		"empty":           nil,
		"image data only": {0xFF, 0xD8, 0xFF, 0xDA},
		"truncated":       testJPEG(t, 4, 4, 0)[:40],
		"truncated EXIF":  append([]byte{0xFF, 0xD8}, exifSegment(binary.BigEndian, 6)[:10]...),
		"short segment":   {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x01},
		"lossless":        jpegFrame(0xC3, 8, 8, 0x11),
		"arithmetic":      jpegFrame(0xC9, 8, 8, 0x11),
		"no width":        jpegFrame(0xC0, 0, 8, 0x11),
		"two components":  jpegFrame(0xC0, 8, 8, 0x11, 0x11),
		"short frame":     {0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x05, 8, 0, 8},
		"garbage":         {0xFF, 0xD8, 0x00, 0xFF, 0xC0},
	} {
		if _, err := read(data); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestDecodeCost(t *testing.T) {
	for _, c := range []struct {
		model  color.Model
		format string
		cost   int64
	}{
		{color.GrayModel, "png", 150},
		{color.NRGBAModel, "png", 600},
		{color.NRGBA64Model, "png", 1200},
		{color.Palette{color.Black}, "gif", 100},
		{nil, "gif", 400},
		{color.RGBAModel, "bmp", 400},
		{color.YCbCrModel, "webp", 400},
		{color.NRGBAModel, "webp", 800},
	} {
		if got := decodeCost(image.Config{ColorModel: c.model, Width: 10, Height: 10}, c.format); got != c.cost {
			t.Errorf("%T %s: %d; want %d", c.model, c.format, got, c.cost)
		}
	}
}

func TestOrient(t *testing.T) {
	// A 3×2 image whose pixels say where they are.
	src := image.NewRGBA(image.Rect(0, 0, 3, 2))
	for y := range 2 {
		for x := range 3 {
			src.SetRGBA(x, y, color.RGBA{uint8(x), uint8(y), 0, 255})
		}
	}
	at := func(img *image.RGBA, x, y int) [2]uint8 {
		c := img.RGBAAt(x, y)
		return [2]uint8{c.R, c.G}
	}
	for o, want := range map[int]struct {
		w, h     int
		topLeft  [2]uint8 // the source pixel that ends up at the top left
		topRight [2]uint8
	}{
		1: {3, 2, [2]uint8{0, 0}, [2]uint8{2, 0}},
		2: {3, 2, [2]uint8{2, 0}, [2]uint8{0, 0}},
		3: {3, 2, [2]uint8{2, 1}, [2]uint8{0, 1}},
		4: {3, 2, [2]uint8{0, 1}, [2]uint8{2, 1}},
		5: {2, 3, [2]uint8{0, 0}, [2]uint8{0, 1}},
		6: {2, 3, [2]uint8{0, 1}, [2]uint8{0, 0}},
		7: {2, 3, [2]uint8{2, 1}, [2]uint8{2, 0}},
		8: {2, 3, [2]uint8{2, 0}, [2]uint8{2, 1}},
	} {
		got := orient(src, o)
		if b := got.Bounds(); b.Dx() != want.w || b.Dy() != want.h || at(got, 0, 0) != want.topLeft || at(got, b.Dx()-1, 0) != want.topRight {
			t.Errorf("orientation %d: %dx%d, top left %v, top right %v", o, b.Dx(), b.Dy(), at(got, 0, 0), at(got, b.Dx()-1, 0))
		}
	}
}

func TestMakeThumb(t *testing.T) {
	decode := func(data []byte) image.Image {
		t.Helper()
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	data, ctype, err := makeThumb(bytes.NewReader(testJPEG(t, 800, 600, 0)))
	if b := decode(data).Bounds(); err != nil || ctype != "image/jpeg" || b.Dx() != 256 || b.Dy() != 192 {
		t.Errorf("landscape: %s %v %v", ctype, b, err)
	}
	// Turned by EXIF: upright in the thumbnail.
	data, _, _ = makeThumb(bytes.NewReader(testJPEG(t, 800, 600, 6)))
	if b := decode(data).Bounds(); b.Dx() != 192 || b.Dy() != 256 {
		t.Errorf("EXIF orientation not applied: %v", b)
	}
	// Small images are not enlarged; transparent ones stay PNG.
	data, ctype, _ = makeThumb(bytes.NewReader(testPNG(t, 40, 30, true)))
	if b := decode(data).Bounds(); ctype != "image/png" || b.Dx() != 40 || b.Dy() != 30 {
		t.Errorf("small transparent: %s %v", ctype, b)
	}
	if _, ctype, _ := makeThumb(bytes.NewReader(testPNG(t, 40, 30, false))); ctype != "image/jpeg" {
		t.Errorf("opaque PNG: %s", ctype)
	}
	// Images that would take too much memory are refused before decoding,
	// as decompression bombs would be.
	png := func(w, h uint32) []byte {
		data := testPNG(t, 1, 1, false)
		binary.BigEndian.PutUint32(data[16:], w) // IHDR width
		binary.BigEndian.PutUint32(data[20:], h) // and height
		binary.BigEndian.PutUint32(data[29:], crc32.ChecksumIEEE(data[12:29]))
		return data
	}
	for name, data := range map[string][]byte{
		"huge":        png(20000, 20000),
		"tall":        png(1, 1<<30),
		"progressive": jpegFrame(0xC2, 8000, 6000, 0x22, 0x11, 0x11),
		"CMYK":        jpegFrame(0xC0, 8000, 6000, 0x11, 0x11, 0x11, 0x11),
		// Decoded in 256 MB, but scaled with a buffer of 32 bytes per
		// pixel of its height times the thumbnail's width.
		"scaled":    jpegFrame(0xC0, 16000, 16000, 0x11),
		"no pixels": []byte("GIF89a\x00\x00\x00\x00\x00\x00\x00;"),
	} {
		if _, _, err := makeThumb(bytes.NewReader(data)); err != errNoThumb {
			t.Errorf("%s: %v", name, err)
		}
	}
	// But not for being large.
	if _, _, err := makeThumb(bytes.NewReader(jpegFrame(0xC0, 8000, 6000, 0x22, 0x11, 0x11))); err == errNoThumb || err == nil {
		t.Errorf("large baseline JPEG: %v", err)
	}
	if _, _, err := makeThumb(bytes.NewReader(png(7680, 4320))); err == errNoThumb || err == nil {
		t.Errorf("8K PNG: %v", err)
	}
	if _, _, err := makeThumb(strings.NewReader("not an image")); err == nil {
		t.Error("made a thumbnail of text")
	}
}

func TestThumbCache(t *testing.T) {
	dir := t.TempDir()
	tc := newThumbCache(dir, 1000, zap.NewNop())
	if tc == nil {
		t.Fatal("no cache")
	}
	key := strings.Repeat("ab", 32)
	if _, _, ok := tc.get(key); ok {
		t.Error("empty cache hit")
	}
	tc.put(key, "image/png", []byte("png data"))
	if data, ctype, ok := tc.get(key); !ok || ctype != "image/png" || string(data) != "png data" {
		t.Errorf("get: %q %s %v", data, ctype, ok)
	}
	// Past its size, the least recently used go.
	for i := range 20 {
		k := strings.Repeat(string(rune('a'+i%6)), 64)
		tc.put(k, "image/jpeg", bytes.Repeat([]byte("x"), 100))
	}
	waitFor(t, "eviction", func() bool {
		tc.mu.Lock()
		defer tc.mu.Unlock()
		return !tc.evicting && tc.used <= 1000
	})
	if newThumbCache(dir, 0, zap.NewNop()) != nil {
		t.Error("a cache of size 0")
	}
	if newThumbCache(filepath.Join(dir, "file"), 1000, zap.NewNop()) == nil {
		t.Error("cache dir not created")
	}
	if err := os.WriteFile(filepath.Join(dir, "blocked"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if newThumbCache(filepath.Join(dir, "blocked"), 1000, zap.NewNop()) != nil {
		t.Error("a cache where there is a file")
	}
}

const (
	testPDF = "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
	testMP4 = "\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"
	testMP3 = "ID3\x04\x00\x00\x00\x00\x00\x00"
	// testHTML is named like an image, to be shown as one.
	testHTML = "<!DOCTYPE html><html><script>alert(1)</script>"
)

func expectHeaders(t *testing.T, resp *http.Response, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s: %s %q, want %q", resp.Request.URL, k, got, v)
		}
	}
}

func TestInline(t *testing.T) {
	f := newFixture(t)
	jpg := string(testJPEG(t, 40, 30, 0))
	f.write(t, "pics/a b.jpg", jpg)
	f.write(t, "pics/page.jpg", testHTML)
	f.write(t, "pics/logo.svg", `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	f.write(t, "docs/r.pdf", testPDF)
	f.write(t, "notes.txt", "hello")

	resp, body := f.do(t, "GET", "/pics/a%20b.jpg?inline")
	expectStatus(t, resp, http.StatusOK)
	// Shown, but as sandboxed as downloads, and only on this site.
	expectHeaders(t, resp, map[string]string{
		"Content-Type":                 "image/jpeg",
		"Content-Disposition":          `inline; filename="a b.jpg"`,
		"Content-Security-Policy":      mediaPolicy,
		"X-Frame-Options":              "SAMEORIGIN",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Content-Type-Options":       "nosniff",
		"Cache-Control":                "no-store",
		"Accept-Ranges":                "bytes",
	})
	if body != jpg {
		t.Error("the image differs")
	}
	// Ranges, which players ask for.
	resp, body = f.do(t, "GET", "/pics/a%20b.jpg?inline", "Range", "bytes=0-9")
	expectStatus(t, resp, http.StatusPartialContent)
	expectHeaders(t, resp, map[string]string{"Content-Type": "image/jpeg", "Content-Disposition": `inline; filename="a b.jpg"`})
	if body != jpg[:10] {
		t.Errorf("range: %q", body)
	}
	resp, body = f.do(t, "HEAD", "/pics/a%20b.jpg?inline")
	expectStatus(t, resp, http.StatusOK)
	if resp.Header.Get("Content-Type") != "image/jpeg" || body != "" {
		t.Errorf("HEAD: %q %q", resp.Header.Get("Content-Type"), body)
	}
	resp, _ = f.do(t, "GET", "/docs/r.pdf?inline")
	expectStatus(t, resp, http.StatusOK)
	expectHeaders(t, resp, map[string]string{"Content-Type": "application/pdf", "Content-Disposition": "inline; filename=r.pdf", "Content-Security-Policy": pdfPolicy})

	// Downloads stay attachments that may not be framed.
	resp, _ = f.do(t, "GET", "/pics/a%20b.jpg")
	expectHeaders(t, resp, map[string]string{
		"Content-Disposition": `attachment; filename="a b.jpg"`, "Content-Security-Policy": fileSecurityPolicy, "X-Frame-Options": "DENY",
	})

	// What could run scripts is never shown, whatever its name.
	for _, p := range []string{"/pics/page.jpg", "/pics/logo.svg", "/notes.txt"} {
		resp, body := f.do(t, "GET", p+"?inline", "Accept", "text/html")
		if resp.StatusCode != http.StatusUnsupportedMediaType || !strings.Contains(body, "cannot be shown in the browser") ||
			strings.Contains(body, "alert(1)") || resp.Header.Get("Content-Disposition") != "" {
			t.Errorf("%s: %d %q %s", p, resp.StatusCode, resp.Header.Get("Content-Disposition"), body)
		}
	}
	for _, p := range []string{"/pics/nope.jpg", "/pics/.hidden.jpg", "/pics/"} {
		if resp, _ := f.do(t, "GET", p+"?inline"); resp.StatusCode == http.StatusOK && p != "/pics/" || resp.Header.Get("Content-Disposition") != "" {
			t.Errorf("%s: %d %q", p, resp.StatusCode, resp.Header.Get("Content-Disposition"))
		}
	}
}

// previewFolder writes files of every kind into pics/ and returns their
// names, in the order the viewer goes through them.
func previewFolder(t *testing.T, f *fixture) []string {
	t.Helper()
	jpg := string(testJPEG(t, 8, 8, 0))
	shown := []string{"a.jpg", "b.jpg", "c.png", "d.mp4", "e.mp3", "f.pdf", "g-fake.jpg", "h #1.jpg"}
	for name, content := range map[string]string{
		"a.jpg": jpg, "b.jpg": jpg, "c.png": string(testPNG(t, 2, 2, false)), "d.mp4": testMP4, "e.mp3": testMP3,
		"f.pdf": testPDF, "g-fake.jpg": testHTML, "h #1.jpg": jpg,
		"notes.txt": "n", ".hidden.jpg": jpg, "sub/x.jpg": jpg,
	} {
		f.write(t, "pics/"+name, content)
	}
	return shown
}

// position matches where the viewer says a file is in its folder.
var position = regexp.MustCompile(`· \d+ of \d+`)

func TestViewer(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	previewFolder(t, f)
	f.write(t, "top.jpg", string(testJPEG(t, 8, 8, 0)))
	view := func(f *fixture, p string) (*http.Response, string) {
		t.Helper()
		return f.do(t, "GET", p+"?view", "Accept", "text/html")
	}

	resp, body := view(f, "/pics/b.jpg")
	expectStatus(t, resp, http.StatusOK)
	for _, want := range []string{
		"<h1>b.jpg</h1>", `<img src="/pics/b.jpg?inline" alt="b.jpg">`, `href="/pics/b.jpg" download`, "2 of 8",
		`id="prev" href="/pics/a.jpg?view"`, `id="next" href="/pics/c.png?view"`, `data-folder="/pics/"`, `<a href="/pics/">pics</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("b.jpg: no %s", want)
		}
	}
	for p, wants := range map[string][]string{
		"/pics/a.jpg":        {"1 of 8", `id="next" href="/pics/b.jpg?view"`},
		"/pics/d.mp4":        {`<video src="/pics/d.mp4?inline" controls`},
		"/pics/e.mp3":        {`<audio src="/pics/e.mp3?inline" controls`},
		"/pics/f.pdf":        {`<iframe src="/pics/f.pdf?inline" title="f.pdf">`, "Open the PDF on its own"},
		"/pics/g-fake.jpg":   {"cannot be shown in the browser", "7 of 8", `id="next" href="/pics/h%20%231.jpg?view"`},
		"/pics/h%20%231.jpg": {"<h1>h #1.jpg</h1>", `<img src="/pics/h%20%231.jpg?inline"`, "8 of 8", `id="prev" href="/pics/g-fake.jpg?view"`},
		"/pics/notes.txt":    {"cannot be shown in the browser", `href="/pics/notes.txt" download`},
		"/top.jpg":           {`<img src="/top.jpg?inline"`, `data-folder="/"`, "1 of 1"},
		"/pics/sub/x.jpg":    {`<a href="/pics/sub/">sub</a>`, "1 of 1"},
	} {
		resp, body := view(f, p)
		expectStatus(t, resp, http.StatusOK)
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("%s: no %s", p, want)
			}
		}
	}
	for p, unwanted := range map[string][]string{
		"/pics/a.jpg":        {`id="prev"`},
		"/pics/h%20%231.jpg": {`id="next"`},
		"/pics/g-fake.jpg":   {"<img", "alert(1)"},
		"/pics/notes.txt":    {`id="prev"`, `id="next"`, "<iframe"},
		"/top.jpg":           {`id="prev"`, `id="next"`},
	} {
		_, body := view(f, p)
		for _, u := range unwanted {
			if strings.Contains(body, u) {
				t.Errorf("%s: %s", p, u)
			}
		}
	}

	if _, body := view(f, "/pics/notes.txt"); position.MatchString(body) {
		t.Error("notes.txt has a position among the files shown")
	}

	// Listings lead to it, with thumbnails of the images Go decodes.
	_, body = f.do(t, "GET", "/pics/", "Accept", "text/html")
	for want, shown := range map[string]bool{
		`href="/pics/a.jpg?view"`: true, `href="/pics/d.mp4?view"`: true, `href="/pics/notes.txt"`: true, `href="/pics/notes.txt?view"`: false,
		`<img class="thumb" src="/pics/a.jpg?thumb"`: true, `src="/pics/c.png?thumb"`: true, `src="/pics/d.mp4?thumb"`: false,
		`src="/pics/f.pdf?thumb"`: false, `src="/pics/notes.txt?thumb"`: false,
	} {
		if strings.Contains(body, want) != shown {
			t.Errorf("listing: %s shown = %v", want, !shown)
		}
	}

	// The viewer goes through what the visitor may read.
	bob := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "bob", "user")}
	dave := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "dave", "user")}
	for _, user := range []string{"bob", "dave"} {
		if _, err := ta.svc.Enforcer().DeleteRolesForUser(auth.Subject(user)); err != nil {
			t.Fatal(err)
		}
	}
	for _, rule := range [][2]string{{"bob", "/pics/"}, {"bob", "/pics/a.jpg"}, {"bob", "/pics/c.png"}, {"dave", "/pics/c.png"}} {
		if _, err := ta.svc.AddPolicy(auth.Subject(rule[0]), rule[1], auth.ActRead); err != nil {
			t.Fatal(err)
		}
	}
	_, body = view(bob, "/pics/c.png")
	if !strings.Contains(body, "2 of 2") || !strings.Contains(body, `id="prev" href="/pics/a.jpg?view"`) || strings.Contains(body, `id="next"`) || strings.Contains(body, "b.jpg") {
		t.Errorf("bob's viewer goes elsewhere: %s", body)
	}
	// dave may not list the folder: nothing around the file is shown.
	_, body = view(dave, "/pics/c.png")
	if !strings.Contains(body, `<img src="/pics/c.png?inline"`) || position.MatchString(body) || strings.Contains(body, "a.jpg") {
		t.Errorf("dave's viewer: %s", body)
	}
	for _, q := range []string{"view", "inline", "thumb"} {
		if resp, _ := bob.do(t, "GET", "/pics/b.jpg?"+q); resp.StatusCode != http.StatusForbidden {
			t.Errorf("bob ?%s of b.jpg: %d", q, resp.StatusCode)
		}
		if resp, _ := f.as("").do(t, "GET", "/pics/a.jpg?"+q); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous ?%s: %d", q, resp.StatusCode)
		}
	}
}

func TestThumbnails(t *testing.T) {
	cache := t.TempDir()
	f := newFixture(t, func(c *config.Config) { c.Cache = config.CacheConfig{Dir: cache, MaxSize: 1 << 20} })
	jpg := testJPEG(t, 800, 600, 0)
	f.write(t, "pics/big.jpg", string(jpg))
	f.write(t, "pics/turned.jpg", string(testJPEG(t, 800, 600, 6)))
	f.write(t, "pics/small.png", string(testPNG(t, 40, 30, true)))
	f.write(t, "pics/fake.jpg", testHTML)
	f.write(t, "pics/broken.jpg", string(jpg[:200]))
	f.write(t, "pics/r.pdf", testPDF)
	thumb := func(p string, headers ...string) (*http.Response, image.Image) {
		t.Helper()
		resp, body := f.do(t, "GET", p+"?thumb", headers...)
		if resp.StatusCode != http.StatusOK {
			return resp, nil
		}
		img, _, err := image.Decode(strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return resp, img
	}

	resp, img := thumb("/pics/big.jpg")
	expectStatus(t, resp, http.StatusOK)
	expectHeaders(t, resp, map[string]string{
		"Content-Type": "image/jpeg", "Cache-Control": "private, no-cache", "Content-Security-Policy": fileSecurityPolicy,
		"Cross-Origin-Resource-Policy": "same-origin", "X-Content-Type-Options": "nosniff",
	})
	etag := resp.Header.Get("ETag")
	if b := img.Bounds(); b.Dx() != 256 || b.Dy() != 192 || !regexp.MustCompile(`^"t[0-9a-f]{24}"$`).MatchString(etag) {
		t.Errorf("big.jpg: %v %s", b, etag)
	}
	if _, img := thumb("/pics/turned.jpg"); img == nil || img.Bounds().Dx() != 192 || img.Bounds().Dy() != 256 {
		t.Error("turned.jpg is not upright")
	}
	if resp, img := thumb("/pics/small.png"); resp.Header.Get("Content-Type") != "image/png" || img == nil || img.Bounds().Dx() != 40 {
		t.Errorf("small.png: %s", resp.Header.Get("Content-Type"))
	}
	for _, p := range []string{"/pics/fake.jpg", "/pics/broken.jpg", "/pics/r.pdf", "/pics/nope.jpg"} {
		if resp, _ := thumb(p); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	// Files too large to decode are not even read.
	f.write(t, "pics/huge.jpg", string(jpg))
	if err := os.Truncate(filepath.Join(f.dir, "pics/huge.jpg"), thumbMaxBytes+1); err != nil {
		t.Fatal(err)
	}
	if resp, _ := thumb("/pics/huge.jpg"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("huge.jpg: %d", resp.StatusCode)
	}

	// Unchanged images cost a stat; changed ones get a new thumbnail.
	if resp, _ := thumb("/pics/big.jpg", "If-None-Match", etag); resp.StatusCode != http.StatusNotModified {
		t.Errorf("revalidation: %d", resp.StatusCode)
	}
	resp, _ = f.do(t, "HEAD", "/pics/big.jpg?thumb")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != etag {
		t.Errorf("HEAD: %d %s", resp.StatusCode, resp.Header.Get("ETag"))
	}
	f.write(t, "pics/big.jpg", string(testJPEG(t, 400, 100, 0)))
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(filepath.Join(f.dir, "pics/big.jpg"), later, later); err != nil {
		t.Fatal(err)
	}
	resp, img = thumb("/pics/big.jpg", "If-None-Match", etag)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") == etag || img.Bounds().Dx() != 256 || img.Bounds().Dy() != 64 {
		t.Errorf("changed image: %d %s", resp.StatusCode, resp.Header.Get("ETag"))
	}

	// Thumbnails are kept, and served from the cache.
	var kept []string
	_ = filepath.WalkDir(cache, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			kept = append(kept, p)
		}
		return nil
	})
	if len(kept) != 4 {
		t.Fatalf("cached %v", kept)
	}
	for _, p := range kept {
		if strings.HasSuffix(p, ".png") {
			if err := os.WriteFile(p, []byte("from the cache"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, body := f.do(t, "GET", "/pics/small.png?thumb"); body != "from the cache" {
		t.Errorf("not from the cache: %.40q", body)
	}

	// When too many are being made, the rest wait their turn, for a while.
	f.srv.thumbWait = 10 * time.Millisecond
	for range cap(f.srv.thumbing) {
		f.srv.thumbing <- struct{}{}
	}
	resp, _ = thumb("/pics/turned.jpg?x")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("cached thumbnail while busy: %d", resp.StatusCode)
	}
	f.write(t, "pics/new.jpg", string(jpg))
	resp, _ = thumb("/pics/new.jpg")
	// Not kept by the browser, which would then revalidate it for good.
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("busy: %d %q %q", resp.StatusCode, resp.Header.Get("Retry-After"), resp.Header.Get("Cache-Control"))
	}
	for range cap(f.srv.thumbing) {
		<-f.srv.thumbing
	}
	if resp, _ := thumb("/pics/new.jpg"); resp.StatusCode != http.StatusOK {
		t.Errorf("no longer busy: %d", resp.StatusCode)
	}
}

func TestSharePreviews(t *testing.T) {
	f := newFixture(t)
	shown := previewFolder(t, f)
	f.write(t, "doc.pdf", testPDF)
	f.write(t, "notes.txt", "n")
	folder := sharePrefix + createShare(t, f, "admin", "/pics", "1h", "")
	visitor := f.as("")

	_, body := visitor.do(t, "GET", folder+"/", "Accept", "text/html")
	for _, want := range []string{`href="` + folder + `/a.jpg?view"`, `<img class="thumb" src="` + folder + `/a.jpg?thumb"`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing: no %s", want)
		}
	}
	resp, body := visitor.do(t, "GET", folder+"/b.jpg?view", "Accept", "text/html")
	expectStatus(t, resp, http.StatusOK)
	for _, want := range []string{
		`<img src="` + folder + `/b.jpg?inline"`, `href="` + folder + `/b.jpg" download`, `data-folder="` + folder + `/"`,
		`id="prev" href="` + folder + `/a.jpg?view"`, "2 of " + strconv.Itoa(len(shown)), "Shared by",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("viewer: no %s", want)
		}
	}
	_, body = visitor.do(t, "GET", folder+"/sub/x.jpg?view", "Accept", "text/html")
	if !strings.Contains(body, `<a href="`+folder+`/sub/">sub</a>`) || !strings.Contains(body, `href="`+folder+`/"`) || strings.Contains(body, `"/pics`) {
		t.Errorf("viewer in a subfolder: %s", body)
	}
	for q, ctype := range map[string]string{"inline": "image/jpeg", "thumb": "image/jpeg"} {
		resp, _ := visitor.do(t, "GET", folder+"/a.jpg?"+q)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != ctype {
			t.Errorf("?%s: %d %s", q, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}

	// A link to a file shows it on its page.
	pdf := sharePrefix + createShare(t, f, "admin", "/doc.pdf", "1h", "")
	resp, body = visitor.do(t, "GET", pdf+"/", "Accept", "text/html")
	expectStatus(t, resp, http.StatusOK)
	if !strings.Contains(body, `<iframe class="share-preview share-pdf" src="`+pdf+`/doc.pdf?inline" title="doc.pdf">`) || !strings.Contains(body, `<main class="container">`) {
		t.Errorf("PDF link: %s", body)
	}
	resp, _ = visitor.do(t, "GET", pdf+"/doc.pdf?inline")
	expectStatus(t, resp, http.StatusOK)
	expectHeaders(t, resp, map[string]string{"Content-Type": "application/pdf", "Content-Disposition": "inline; filename=doc.pdf", "Content-Security-Policy": pdfPolicy})
	if resp, _ := visitor.do(t, "GET", pdf+"/doc.pdf?view"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != pdf+"/" {
		t.Errorf("?view of a file link: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	notes := sharePrefix + createShare(t, f, "admin", "/notes.txt", "1h", "")
	if _, body := visitor.do(t, "GET", notes+"/", "Accept", "text/html"); strings.Contains(body, `class="share-preview`) || !strings.Contains(body, `<main class="container narrow">`) {
		t.Errorf("text link: %s", body)
	}
	fake := sharePrefix + createShare(t, f, "admin", "/pics/g-fake.jpg", "1h", "")
	if _, body := visitor.do(t, "GET", fake+"/", "Accept", "text/html"); strings.Contains(body, `class="share-preview`) || strings.Contains(body, "?inline") {
		t.Error("a page named like an image is shown")
	}

	// Without the password, nothing is shown.
	locked := sharePrefix + createShare(t, f, "admin", "/pics", "1h", "correct horse")
	for _, q := range []string{"inline", "thumb", "view"} {
		resp, body := visitor.do(t, "GET", locked+"/a.jpg?"+q)
		if resp.StatusCode != http.StatusForbidden || strings.Contains(body, "JFIF") {
			t.Errorf("locked ?%s: %d", q, resp.StatusCode)
		}
	}
}
