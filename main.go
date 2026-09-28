package main

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	rootDir     string
	addr        string
	secureQuery string
	secureKey   string
)

type fileEntry struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
	Path    string
	SizeStr string
}

func main() {
	flag.StringVar(&rootDir, "dir", ".", "directory to serve")
	flag.StringVar(&addr, "addr", ":8080", "listen address")
	flag.StringVar(&secureQuery, "query", "key", "secure query parameter name")
	flag.Parse()

	secureKey = os.Getenv("SECURE_KEY")
	if secureKey == "" {
		log.Fatal("SECURE_KEY environment variable is required")
	}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		log.Fatalf("invalid directory: %v", err)
	}
	// Resolve symlinks on the root itself so all later comparisons
	// against EvalSymlinks results are consistent.
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		log.Fatalf("cannot resolve root path: %v", err)
	}
	rootDir = realRoot

	info, err := os.Stat(rootDir)
	if err != nil || !info.IsDir() {
		log.Fatalf("%q is not a valid directory", rootDir)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	srv := &http.Server{
		Addr:              addr,
		Handler:           logMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	log.Printf("Serving %s on http://localhost%s", rootDir, addr)
	log.Fatal(srv.ListenAndServe())
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		next.ServeHTTP(w, r)
	})
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		securityHeaders(next).ServeHTTP(sr, r)
		log.Printf("%s %s %d %s %s", r.RemoteAddr, r.Method, sr.status, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reqPath := filepath.Join(rootDir, filepath.Clean(r.URL.Path))

	// Block access to dot-files/directories (e.g. .git, .env).
	if containsDotSegment(r.URL.Path) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Lexical check first (cheap, no syscall).
	if !isLexicallyInside(reqPath) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Open first, then verify the real path of the opened fd to eliminate
	// the TOCTOU window between symlink resolution and file access.
	f, err := os.Open(reqPath)
	if os.IsNotExist(err) {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if !verifyOpenedPath(f) {
		f.Close()
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if info.IsDir() {
		f.Close()
		serveDirectory(w, r, reqPath)
		return
	}

	// Auth check for file downloads — must come before any content is sent.
	// Reject early with a minimal response to avoid leaking file metadata.
	if !validKey(r) {
		f.Close()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusForbidden)
		if r.Method != http.MethodHead {
			io.WriteString(w, "SIKTIR\n")
		}
		return
	}

	serveFileFromFd(w, r, f, info)
}

func validKey(r *http.Request) bool {
	provided := r.URL.Query().Get(secureQuery)
	if len(provided) == 0 {
		log.Printf("AUTH DENIED %s %s (no %q parameter)", r.RemoteAddr, r.URL.Path, secureQuery)
		return false
	}
	ok := subtle.ConstantTimeCompare([]byte(provided), []byte(secureKey)) == 1
	if !ok {
		log.Printf("AUTH DENIED %s %s (invalid key)", r.RemoteAddr, r.URL.Path)
	}
	return ok
}

func containsDotSegment(urlPath string) bool {
	for _, seg := range strings.Split(urlPath, "/") {
		if strings.HasPrefix(seg, ".") && len(seg) > 1 {
			return true
		}
	}
	return false
}

func rootPrefix() string {
	return rootDir + string(os.PathSeparator)
}

// isLexicallyInside is a cheap, no-syscall check on the cleaned path.
func isLexicallyInside(target string) bool {
	clean := filepath.Clean(target)
	if clean == rootDir {
		return true
	}
	return strings.HasPrefix(clean+string(os.PathSeparator), rootPrefix())
}

// verifyOpenedPath resolves the real path of an already-opened fd and
// confirms it is still inside rootDir. This closes the TOCTOU window:
// the fd is already open, so even if the filesystem changes after this
// check, we are reading from the correct inode.
func verifyOpenedPath(f *os.File) bool {
	real, err := filepath.EvalSymlinks(f.Name())
	if err != nil {
		return false
	}
	if real == rootDir {
		return true
	}
	return strings.HasPrefix(real+string(os.PathSeparator), rootPrefix())
}

func serveDirectory(w http.ResponseWriter, r *http.Request, dirPath string) {
	if !strings.HasSuffix(r.URL.Path, "/") {
		target := r.URL.Path + "/"
		// Prevent open redirect: collapse leading slashes so
		// "//evil.com/" can't become a protocol-relative redirect.
		for strings.HasPrefix(target, "//") {
			target = target[1:]
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "Cannot read directory", http.StatusInternalServerError)
		return
	}

	var files []fileEntry
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		fe := fileEntry{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			IsDir:   e.IsDir(),
			Path:    path.Join(r.URL.Path, e.Name()),
			SizeStr: formatSize(info.Size()),
		}
		if fe.IsDir {
			fe.Path += "/"
			fe.SizeStr = "—"
		}
		files = append(files, fe)
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
	})

	data := struct {
		Path    string
		Parent  string
		IsRoot  bool
		Files   []fileEntry
		DirName string
	}{
		Path:    r.URL.Path,
		Parent:  path.Dir(strings.TrimSuffix(r.URL.Path, "/")),
		IsRoot:  r.URL.Path == "/",
		Files:   files,
		DirName: filepath.Base(dirPath),
	}
	if data.Parent != "/" {
		data.Parent += "/"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dirTemplate.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

const maxRanges = 64

type byteRange struct {
	start, end int64
}

func serveFileFromFd(w http.ResponseWriter, r *http.Request, f *os.File, info os.FileInfo) {
	defer f.Close()

	size := info.Size()
	modTime := info.ModTime()
	etag := fmt.Sprintf(`"%x-%x"`, modTime.UnixNano(), size)
	contentType := detectContentType(f)

	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{
		"filename": filepath.Base(f.Name()),
	}))

	if match := r.Header.Get("If-None-Match"); match != "" {
		if match == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		serveFull(w, r, f, size, contentType)
		return
	}

	ranges, ok := parseRanges(rangeHeader, size)
	if !ok || len(ranges) == 0 {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		http.Error(w, "Requested range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	if ifRange := r.Header.Get("If-Range"); ifRange != "" {
		if ifRange != etag {
			f.Seek(0, io.SeekStart)
			serveFull(w, r, f, size, contentType)
			return
		}
	}

	if len(ranges) == 1 {
		serveSingleRange(w, r, f, size, contentType, ranges[0])
		return
	}

	serveMultiRange(w, r, f, size, contentType, ranges)
}

func serveFull(w http.ResponseWriter, r *http.Request, f *os.File, size int64, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		io.Copy(w, f)
	}
}

func serveSingleRange(w http.ResponseWriter, r *http.Request, f *os.File, size int64, contentType string, rng byteRange) {
	contentLength := rng.end - rng.start + 1
	f.Seek(rng.start, io.SeekStart)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rng.start, rng.end, size))
	w.WriteHeader(http.StatusPartialContent)

	if r.Method != http.MethodHead {
		io.CopyN(w, f, contentLength)
	}
}

func serveMultiRange(w http.ResponseWriter, r *http.Request, f *os.File, size int64, contentType string, ranges []byteRange) {
	boundary := fmt.Sprintf("%016x%016x", time.Now().UnixNano(), size)
	var parts []partMeta
	totalLen := int64(0)

	for _, rng := range ranges {
		hdr := buildPartHeader(boundary, contentType, rng, size)
		bodyLen := rng.end - rng.start + 1
		parts = append(parts, partMeta{header: hdr, rng: rng, bodyLen: bodyLen})
		totalLen += int64(len(hdr)) + bodyLen + 2 // +2 for trailing CRLF after body
	}
	closing := fmt.Sprintf("--%s--\r\n", boundary)
	totalLen += int64(len(closing))

	w.Header().Set("Content-Type", fmt.Sprintf("multipart/byteranges; boundary=%s", boundary))
	w.Header().Set("Content-Length", strconv.FormatInt(totalLen, 10))
	w.WriteHeader(http.StatusPartialContent)

	if r.Method == http.MethodHead {
		return
	}

	for _, p := range parts {
		w.Write([]byte(p.header))
		f.Seek(p.rng.start, io.SeekStart)
		io.CopyN(w, f, p.bodyLen)
		w.Write([]byte("\r\n"))
	}
	w.Write([]byte(closing))
}

type partMeta struct {
	header  string
	rng     byteRange
	bodyLen int64
}

func buildPartHeader(boundary, contentType string, rng byteRange, totalSize int64) string {
	return fmt.Sprintf("--%s\r\n%s: %s\r\n%s: bytes %d-%d/%d\r\n\r\n",
		boundary,
		textproto.CanonicalMIMEHeaderKey("Content-Type"), contentType,
		textproto.CanonicalMIMEHeaderKey("Content-Range"),
		rng.start, rng.end, totalSize,
	)
}

// parseRanges parses an RFC 7233 Range header, returning up to maxRanges
// validated byte ranges. Overlapping and out-of-order ranges are allowed
// (download managers may request them). The total bytes requested across
// all ranges is capped at 2x the file size to prevent amplification attacks
// where an attacker sends many overlapping ranges to multiply bandwidth.
func parseRanges(rangeHeader string, fileSize int64) ([]byteRange, bool) {
	if fileSize == 0 {
		return nil, false
	}
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, false
	}
	specs := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), ",")
	if len(specs) > maxRanges {
		return nil, false
	}

	var ranges []byteRange
	var totalBytes int64
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		rng, ok := parseSingleRange(spec, fileSize)
		if !ok {
			return nil, false
		}
		totalBytes += rng.end - rng.start + 1
		if totalBytes > fileSize*2 {
			return nil, false
		}
		ranges = append(ranges, rng)
	}
	if len(ranges) == 0 {
		return nil, false
	}
	return ranges, true
}

func parseSingleRange(spec string, fileSize int64) (byteRange, bool) {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return byteRange{}, false
	}
	startStr, endStr := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

	if startStr == "" {
		suffix, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || suffix <= 0 {
			return byteRange{}, false
		}
		if suffix > fileSize {
			suffix = fileSize
		}
		return byteRange{start: fileSize - suffix, end: fileSize - 1}, true
	}

	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 || start >= fileSize {
		return byteRange{}, false
	}

	if endStr == "" {
		return byteRange{start: start, end: fileSize - 1}, true
	}

	end, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil || end < start {
		return byteRange{}, false
	}
	if end >= fileSize {
		end = fileSize - 1
	}

	return byteRange{start: start, end: end}, true
}

func detectContentType(f *os.File) string {
	pos, _ := f.Seek(0, io.SeekCurrent)
	defer f.Seek(pos, io.SeekStart)

	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	if n == 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(buf[:n])
}

func formatSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

var dirTemplate = template.Must(template.New("dir").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.DirName}} — goftp</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #181b23;
    --border: #262a36;
    --text: #e0e1e6;
    --text-dim: #8b8d98;
    --accent: #6e9eff;
    --accent-hover: #88b4ff;
    --folder: #f0c36d;
    --file: #8b8d98;
    --hover-bg: #1e2230;
    --radius: 8px;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    min-height: 100vh;
  }
  .container {
    max-width: 860px;
    margin: 0 auto;
    padding: 2rem 1.5rem;
  }
  header {
    margin-bottom: 1.5rem;
  }
  header h1 {
    font-size: 1.2rem;
    font-weight: 600;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  header h1 .logo { color: var(--accent); font-weight: 700; }
  .breadcrumb {
    font-size: 0.85rem;
    color: var(--text-dim);
    margin-top: 0.35rem;
    word-break: break-all;
  }
  .breadcrumb a { color: var(--accent); text-decoration: none; }
  .breadcrumb a:hover { text-decoration: underline; }
  .table-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left;
    padding: 0.65rem 1rem;
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-dim);
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: sticky;
    top: 0;
  }
  td { padding: 0.55rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--hover-bg); }
  .name-cell { display: flex; align-items: center; gap: 0.6rem; }
  .name-cell a { color: var(--text); text-decoration: none; font-weight: 450; }
  .name-cell a:hover { color: var(--accent-hover); }
  .icon { width: 18px; height: 18px; flex-shrink: 0; }
  .icon-folder { color: var(--folder); }
  .icon-file { color: var(--file); }
  .size { color: var(--text-dim); font-variant-numeric: tabular-nums; white-space: nowrap; }
  .date { color: var(--text-dim); white-space: nowrap; font-size: 0.85rem; }
  .parent-link { display: inline-flex; align-items: center; gap: 0.3rem; margin-bottom: 0.75rem; }
  .parent-link a { color: var(--accent); text-decoration: none; font-size: 0.85rem; }
  .parent-link a:hover { text-decoration: underline; }
  .empty {
    padding: 2rem 1rem;
    text-align: center;
    color: var(--text-dim);
    font-size: 0.9rem;
  }
  footer {
    margin-top: 2rem;
    text-align: center;
    font-size: 0.75rem;
    color: var(--text-dim);
  }
  @media (max-width: 600px) {
    .container { padding: 1rem; }
    .date-col { display: none; }
    td, th { padding: 0.5rem 0.75rem; }
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span class="logo">goftp</span></h1>
    <div class="breadcrumb">{{.Path}}</div>
  </header>

  {{if not .IsRoot}}
  <div class="parent-link">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg>
    <a href="{{.Parent}}">Parent directory</a>
  </div>
  {{end}}

  <div class="table-wrap">
  {{if .Files}}
    <table>
      <thead><tr>
        <th>Name</th>
        <th style="width:100px; text-align:right">Size</th>
        <th class="date-col" style="width:160px; text-align:right">Modified</th>
      </tr></thead>
      <tbody>
      {{range .Files}}
        <tr>
          <td>
            <div class="name-cell">
              {{if .IsDir}}
              <svg class="icon icon-folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>
              {{else}}
              <svg class="icon icon-file" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              {{end}}
              <a href="{{.Path}}">{{.Name}}</a>
            </div>
          </td>
          <td class="size" style="text-align:right">{{.SizeStr}}</td>
          <td class="date date-col" style="text-align:right">{{.ModTime.Format "Jan 02, 2006 15:04"}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
  {{else}}
    <div class="empty">This directory is empty.</div>
  {{end}}
  </div>

  <footer>goftp &middot; resumable file server</footer>
</div>
</body>
</html>
`))
