package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	_ "image/gif" // with JPEG and PNG, the formats thumbnails are made of
	"image/jpeg"
	"image/png"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	_ "golang.org/x/image/bmp"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

// Thumbnails are at most thumbSize pixels wide and high. Images that would
// take more than thumbMaxMemory to make one of, or files over thumbMaxBytes,
// get none. thumbVersion changes with how thumbnails are made.
const (
	thumbSize      = 256
	thumbMaxMemory = 256 << 20
	thumbMaxBytes  = 100 << 20
	thumbVersion   = "1"
)

var errNoThumb = errors.New("no thumbnail for this file")

// thumbable reports whether a thumbnail can be made of a file whose content
// sniffs as ctype.
func thumbable(ctype string) bool {
	switch ctype {
	case "image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp":
		return true
	}
	return false
}

// serveThumb answers with a thumbnail of the image f (taking ownership of
// it), which lives at realPath. Browsers revalidate it with its ETag, which
// changes with the image, so unchanged thumbnails cost a stat.
func (s *Server) serveThumb(c fiber.Ctx, f *os.File, info fs.FileInfo, realPath string) error {
	defer f.Close()
	sum := sha256.Sum256([]byte(thumbVersion + "\x00" + realPath + "\x00" +
		strconv.FormatInt(info.Size(), 10) + "\x00" + strconv.FormatInt(info.ModTime().UnixNano(), 10)))
	key := hex.EncodeToString(sum[:])
	etag := `"t` + key[:24] + `"`
	c.Set(fiber.HeaderETag, etag)
	c.Set(fiber.HeaderCacheControl, "private, no-cache")
	c.Set(fiber.HeaderContentSecurityPolicy, fileSecurityPolicy)
	if notModified(c.Get(fiber.HeaderIfNoneMatch), "", etag, time.Time{}) {
		return c.SendStatus(fiber.StatusNotModified)
	}
	if ctype, _ := inlineType(f, ""); !thumbable(ctype) || info.Size() > thumbMaxBytes {
		return fiber.ErrNotFound
	}
	data, ctype, ok := s.thumbs.get(key)
	if !ok {
		var err error
		if data, ctype, err = s.makeThumbInTurn(f); err != nil {
			if err == errThumbsBusy {
				retryAfter(c, time.Second)
				return fiber.ErrServiceUnavailable
			}
			return fiber.ErrNotFound
		}
		s.thumbs.put(key, ctype, data)
	}
	c.Set(fiber.HeaderContentType, ctype)
	return c.Send(data)
}

var errThumbsBusy = errors.New("busy making thumbnails")

// makeThumbInTurn makes a thumbnail of r, as one of at most
// thumbConcurrency() at once, waiting up to s.thumbWait for its turn.
func (s *Server) makeThumbInTurn(r io.ReadSeeker) ([]byte, string, error) {
	select {
	case s.thumbing <- struct{}{}:
		defer func() { <-s.thumbing }()
	case <-time.After(s.thumbWait):
		return nil, "", errThumbsBusy
	}
	return makeThumb(r)
}

// makeThumb decodes the image in r and returns a thumbnail of it: a JPEG,
// or a PNG if it is transparent somewhere.
func makeThumb(r io.ReadSeeker) ([]byte, string, error) {
	cfg, format, err := image.DecodeConfig(bufio.NewReader(r))
	if err != nil {
		return nil, "", err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, "", errNoThumb
	}
	pixels := int64(cfg.Width) * int64(cfg.Height)
	orientation, cost := 1, decodeCost(cfg, format)
	if format == "jpeg" {
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, "", err
		}
		h, err := readJPEGHeader(bufio.NewReader(r))
		if err != nil {
			return nil, "", err
		}
		orientation, cost = h.orientation, h.cost
		if cfg.ColorModel == color.RGBAModel || cfg.ColorModel == color.CMYKModel {
			cost += 4 * pixels // converted from its planes once decoded
		}
	}
	// Scaling takes 32 bytes per pixel of the image's height times the
	// thumbnail's width.
	w, _ := thumbDims(cfg.Width, cfg.Height)
	if cost+32*int64(w)*int64(cfg.Height) > thumbMaxMemory {
		return nil, "", errNoThumb
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}
	src, _, err := image.Decode(bufio.NewReader(r))
	if err != nil {
		return nil, "", err
	}
	b := src.Bounds()
	w, h := thumbDims(b.Dx(), b.Dy())
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.BiLinear.Scale(dst, dst.Bounds(), src, b, draw.Src, nil)
	dst = orient(dst, orientation)

	var buf bytes.Buffer
	if dst.Opaque() {
		err = jpeg.Encode(&buf, dst, &jpeg.Options{Quality: 82})
		return buf.Bytes(), "image/jpeg", err
	}
	err = png.Encode(&buf, dst)
	return buf.Bytes(), "image/png", err
}

// thumbDims returns the size of the thumbnail of a w×h image: as large as
// fits in thumbSize×thumbSize, but never larger than the image.
func thumbDims(w, h int) (int, int) {
	if scale := float64(thumbSize) / float64(max(w, h)); scale < 1 {
		return max(1, int(float64(w)*scale+0.5)), max(1, int(float64(h)*scale+0.5))
	}
	return w, h
}

// decodeCost estimates, on the high side, the memory decoding an image
// other than a JPEG takes, in bytes.
func decodeCost(cfg image.Config, format string) int64 {
	perPixel := int64(4)
	switch cfg.ColorModel {
	case color.GrayModel, color.AlphaModel:
		perPixel = 1
	case color.Gray16Model, color.Alpha16Model, color.YCbCrModel:
		perPixel = 2
	case color.RGBA64Model, color.NRGBA64Model:
		perPixel = 8
	default:
		if _, ok := cfg.ColorModel.(color.Palette); ok {
			perPixel = 1
		}
	}
	cost := int64(cfg.Width) * int64(cfg.Height) * perPixel
	switch format {
	case "png":
		cost += cost / 2 // interlaced: decoded a pass at a time, then merged
	case "webp":
		cost *= 2 // lossless: decoded once more if indexed; lossy: alpha
	}
	return cost
}

// jpegHeader is what a JPEG says of itself before its image data.
type jpegHeader struct {
	orientation int   // EXIF orientation, 1 to 8: how to turn it upright
	cost        int64 // the memory image/jpeg takes to decode its planes
}

// readJPEGHeader reads the markers of the JPEG in r up to its frame header,
// or fails if image/jpeg would not decode the frame.
func readJPEGHeader(r io.Reader) (jpegHeader, error) {
	h := jpegHeader{orientation: 1}
	exif := false
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil || b != [2]byte{0xFF, 0xD8} {
		return h, errNoThumb
	}
	for {
		// A marker is 0xFF, any number of times, and its code.
		if _, err := io.ReadFull(r, b[:1]); err != nil || b[0] != 0xFF {
			return h, errNoThumb
		}
		m := b[0]
		for m == 0xFF {
			if _, err := io.ReadFull(r, b[:1]); err != nil {
				return h, errNoThumb
			}
			m = b[0]
		}
		switch {
		case m == 0xD8 || (m >= 0xD0 && m <= 0xD7) || m == 0x01:
			continue // no length
		case m == 0xDA || m == 0xD9:
			return h, errNoThumb // image data or the end, but no frame
		}
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return h, errNoThumb
		}
		n := int(binary.BigEndian.Uint16(b[:])) - 2
		if n < 0 {
			return h, errNoThumb
		}
		switch {
		case m == 0xE1 || m == 0xC0 || m == 0xC1 || m == 0xC2:
			seg := make([]byte, n)
			if _, err := io.ReadFull(r, seg); err != nil {
				return h, errNoThumb
			}
			if m == 0xE1 { // APP1, which may hold EXIF data
				if o, ok := tiffOrientation(seg); ok && !exif {
					h.orientation, exif = o, true
				}
				continue
			}
			// The frame: baseline, extended or progressive.
			cost, ok := jpegCost(seg, m == 0xC2)
			if !ok {
				return h, errNoThumb
			}
			h.cost = cost
			return h, nil
		case m >= 0xC3 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC:
			return h, errNoThumb // a kind of frame image/jpeg does not decode
		}
		if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
			return h, errNoThumb
		}
	}
}

// jpegCost returns the memory image/jpeg takes to decode the frame whose
// header is seg: a plane per component as if none were subsampled, and if
// progressive, 4 bytes per sample of coefficients too.
func jpegCost(seg []byte, progressive bool) (int64, bool) {
	if len(seg) < 6 {
		return 0, false
	}
	height, width, n := int64(binary.BigEndian.Uint16(seg[1:])), int64(binary.BigEndian.Uint16(seg[3:])), int(seg[5])
	if width == 0 || height == 0 || (n != 1 && n != 3 && n != 4) || len(seg) < 6+3*n {
		return 0, false
	}
	hs, vs := make([]int64, n), make([]int64, n)
	var maxH, maxV int64 = 1, 1
	for i := range n {
		hv := seg[7+3*i]
		hs[i], vs[i] = max(1, int64(hv>>4)), max(1, int64(hv&15))
		if n == 1 {
			hs[i], vs[i] = 1, 1 // as image/jpeg takes it
		}
		maxH, maxV = max(maxH, hs[i]), max(maxV, vs[i])
	}
	// The image is decoded in units of 8×8 blocks per sampling factor.
	mxx, myy := (width+8*maxH-1)/(8*maxH), (height+8*maxV-1)/(8*maxV)
	cost := int64(n) * 8 * maxH * mxx * 8 * maxV * myy
	if progressive {
		for i := range n {
			cost += mxx * myy * hs[i] * vs[i] * 64 * 4
		}
	}
	return cost, true
}

// tiffOrientation reads the orientation tag from an APP1 segment holding
// EXIF data.
func tiffOrientation(seg []byte) (int, bool) {
	tiff, ok := bytes.CutPrefix(seg, []byte("Exif\x00\x00"))
	if !ok || len(tiff) < 8 {
		return 0, false
	}
	var order binary.ByteOrder
	switch string(tiff[:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return 0, false
	}
	ifd := int(order.Uint32(tiff[4:8]))
	if ifd < 8 || ifd+2 > len(tiff) {
		return 0, false
	}
	entries := int(order.Uint16(tiff[ifd:]))
	for i := range entries {
		e := ifd + 2 + 12*i
		if e+12 > len(tiff) {
			break
		}
		// Tag 0x0112, a SHORT, holds the orientation.
		if order.Uint16(tiff[e:]) == 0x0112 && order.Uint16(tiff[e+2:]) == 3 {
			if o := int(order.Uint16(tiff[e+8:])); o >= 1 && o <= 8 {
				return o, true
			}
		}
	}
	return 0, false
}

// orient turns an image as its EXIF orientation o says.
func orient(src *image.RGBA, o int) *image.RGBA {
	if o < 2 || o > 8 {
		return src
	}
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	dw, dh := w, h
	if o >= 5 {
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := range h {
		for x := range w {
			var dx, dy int
			switch o {
			case 2: // mirrored
				dx, dy = w-1-x, y
			case 3: // upside down
				dx, dy = w-1-x, h-1-y
			case 4: // mirrored upside down
				dx, dy = x, h-1-y
			case 5: // mirrored, turned left
				dx, dy = y, x
			case 6: // turned left: turn right
				dx, dy = h-1-y, x
			case 7: // mirrored, turned right
				dx, dy = h-1-y, w-1-x
			case 8: // turned right: turn left
				dx, dy = y, w-1-x
			}
			dst.SetRGBA(dx, dy, src.RGBAAt(b.Min.X+x, b.Min.Y+y))
		}
	}
	return dst
}

// thumbCache keeps thumbnails on disk, under keys that change with the
// image. When it grows past max, the least recently used ones go. A nil
// cache keeps nothing.
type thumbCache struct {
	dir string
	max int64
	log *zap.Logger

	mu       sync.Mutex
	used     int64
	evicting bool
}

// newThumbCache opens the cache in dir, or returns nil if it cannot be
// used: thumbnails are then made for every request that needs one.
func newThumbCache(dir string, max int64, log *zap.Logger) *thumbCache {
	if max <= 0 {
		return nil
	}
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			log.Warn("no thumbnail cache: set cache.dir", zap.Error(err))
			return nil
		}
		dir = filepath.Join(base, "goftp")
	}
	dir = filepath.Join(dir, "thumbs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Warn("no thumbnail cache", zap.String("dir", dir), zap.Error(err))
		return nil
	}
	tc := &thumbCache{dir: dir, max: max, log: log}
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				tc.used += info.Size()
			}
		}
		return nil
	})
	return tc
}

func (tc *thumbCache) path(key, ctype string) string {
	ext := ".jpg"
	if ctype == "image/png" {
		ext = ".png"
	}
	return filepath.Join(tc.dir, key[:2], key+ext)
}

func (tc *thumbCache) get(key string) ([]byte, string, bool) {
	if tc == nil {
		return nil, "", false
	}
	for _, ctype := range []string{"image/jpeg", "image/png"} {
		p := tc.path(key, ctype)
		if data, err := os.ReadFile(p); err == nil {
			now := time.Now()
			_ = os.Chtimes(p, now, now) // recently used
			return data, ctype, true
		}
	}
	return nil, "", false
}

func (tc *thumbCache) put(key, ctype string, data []byte) {
	if tc == nil {
		return
	}
	p := tc.path(key, ctype)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return
	}
	tc.mu.Lock()
	tc.used += int64(len(data))
	over := tc.used > tc.max && !tc.evicting
	tc.evicting = tc.evicting || over
	tc.mu.Unlock()
	if over {
		go tc.evict()
	}
}

// evict removes the least recently used thumbnails until the cache is at
// most three quarters full.
func (tc *thumbCache) evict() {
	type entry struct {
		path string
		size int64
		used time.Time
	}
	var entries []entry
	var total int64
	_ = filepath.WalkDir(tc.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				entries = append(entries, entry{p, info.Size(), info.ModTime()})
				total += info.Size()
			}
		}
		return nil
	})
	slices.SortFunc(entries, func(a, b entry) int { return a.used.Compare(b.used) })
	removed := 0
	for _, e := range entries {
		if total <= tc.max*3/4 {
			break
		}
		if os.Remove(e.path) == nil {
			total -= e.size
			removed++
		}
	}
	tc.mu.Lock()
	tc.used, tc.evicting = total, false
	tc.mu.Unlock()
	tc.log.Debug("thumbnail cache trimmed", zap.Int("removed", removed), zap.Int64("bytes", total))
}

// thumbConcurrency bounds the thumbnails made at once: each decodes an
// image of up to thumbMaxPixels.
func thumbConcurrency() int { return min(2, runtime.GOMAXPROCS(0)) }
