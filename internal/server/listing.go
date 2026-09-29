package server

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"goftp/internal/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

// appJS enhances the pages, which also work without it.
//
//go:embed templates/app.js
var appJS string

// scriptHash admits appJS, and no other script, in the CSP.
var scriptHash = func() string {
	sum := sha256.Sum256([]byte(appJS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"script":  func() template.HTML { return template.HTML("<script>" + appJS + "</script>") },
	"initial": func(s string) string { return strings.ToUpper(s[:min(1, len(s))]) },
}).ParseFS(templateFS, "templates/*.html"))

// page holds what every page shows.
type page struct {
	Title     string
	User      string
	Role      string
	Here      string
	MinLength int
}

func (s *Server) page(c fiber.Ctx, title string) page {
	p := page{Title: title, Here: c.OriginalURL(), MinLength: auth.MinPasswordLength}
	if u := userOf(c); u != nil {
		p.User = u.Username
		p.Role = s.auth.Role(u.Username)
	}
	return p
}

func (s *Server) render(c fiber.Ctx, status int, name string, data any) error {
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, name, data); err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Status(status).Send(buf.Bytes())
}

type listing struct {
	page
	Path     string
	Crumbs   []crumb
	Parent   string
	Items    []listItem
	Upload   *uploadForm
	Sort     string
	Desc     bool
	Summary  string
	Uploaded int
}

type crumb struct {
	Name, Href string
	Current    bool
}

type uploadForm struct {
	Action  string
	Replace bool
}

type listItem struct {
	Name    string
	Key     string // lower-case name, for sorting and filtering
	Href    string
	Kind    string // icon: folder, image, video, ...
	Size    string
	ModTime string
	ModISO  string
	IsDir   bool
	size    int64
	mod     time.Time
}

// SortHref links a column header: a second click reverses the order.
func (l listing) SortHref(col string) string {
	if l.Sort == col && !l.Desc {
		return "?sort=" + col + "&order=desc"
	}
	return "?sort=" + col
}

// SortState is a column's aria-sort value.
func (l listing) SortState(col string) string {
	switch {
	case l.Sort != col:
		return "none"
	case l.Desc:
		return "descending"
	default:
		return "ascending"
	}
}

func (s *Server) serveDir(c fiber.Ctx, dir *os.File, urlPath string, wantDir bool) error {
	if !wantDir && urlPath != "/" {
		return c.Redirect().Status(fiber.StatusMovedPermanently).To(escapePath(urlPath + "/"))
	}

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	// Entries with a live lock file are still being uploaded.
	locked := make(map[string]bool)
	for _, e := range entries {
		if target, ok := lockTarget(e.Name()); ok && s.locked(rootName(urlPath), target) {
			locked[target] = true
		}
	}
	data := listing{page: s.page(c, "All files"), Path: urlPath, Crumbs: crumbs(urlPath)}
	data.Items = make([]listItem, 0, len(entries))
	var (
		dirs, files int
		total       int64
	)
	for _, e := range entries {
		if locked[e.Name()] {
			continue
		}
		item, ok := s.listItem(urlPath, e)
		if !ok {
			continue
		}
		// Only what the visitor may open is listed.
		if ok, err := s.allowed(c, object(path.Join(urlPath, item.Name), item.IsDir), auth.ActRead); err != nil {
			return err
		} else if !ok {
			continue
		}
		data.Items = append(data.Items, item)
		if item.IsDir {
			dirs++
		} else {
			files++
			total += item.size
		}
	}
	data.Summary = summary(dirs, files, total)

	switch c.Query("sort") {
	case "size":
		data.Sort = "size"
	case "modified":
		data.Sort = "modified"
	default:
		data.Sort = "name"
	}
	data.Desc = c.Query("order") == "desc"
	sortItems(data.Items, data.Sort, data.Desc)

	if urlPath != "/" {
		data.Title = path.Base(urlPath)
		data.Parent = escapePath(object(path.Dir(urlPath), true))
	}
	if n, err := strconv.Atoi(c.Query("uploaded")); err == nil && n > 0 {
		data.Uploaded = n
	}
	create, replace, err := s.uploadRights(c, object(urlPath, true))
	if err != nil {
		return err
	}
	if create || replace {
		data.Upload = &uploadForm{Action: escapePath(object(urlPath, true)), Replace: replace}
	}
	return s.render(c, fiber.StatusOK, "listing", data)
}

// sortItems puts directories first, then orders by col, then by name.
func sortItems(items []listItem, col string, desc bool) {
	slices.SortFunc(items, func(a, b listItem) int {
		if a.IsDir != b.IsDir {
			if a.IsDir {
				return -1
			}
			return 1
		}
		n := 0
		switch col {
		case "size":
			n = cmp.Compare(a.size, b.size)
		case "modified":
			n = a.mod.Compare(b.mod)
		}
		if n == 0 {
			n = cmp.Or(strings.Compare(a.Key, b.Key), strings.Compare(a.Name, b.Name))
		}
		if desc {
			return -n
		}
		return n
	})
}

// summary describes a listing, e.g. "3 folders · 10 files · 56.9 MiB".
func summary(dirs, files int, total int64) string {
	var parts []string
	if dirs > 0 {
		parts = append(parts, plural(dirs, "folder"))
	}
	if files > 0 {
		parts = append(parts, plural(files, "file"), formatSize(total))
	}
	if len(parts) == 0 {
		return "Empty folder"
	}
	return strings.Join(parts, " · ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// crumbs links every directory on the way to urlPath.
func crumbs(urlPath string) []crumb {
	var out []crumb
	p := ""
	for _, name := range strings.Split(strings.Trim(urlPath, "/"), "/") {
		if name == "" {
			continue
		}
		p += "/" + name
		out = append(out, crumb{Name: name, Href: escapePath(p + "/")})
	}
	if len(out) > 0 {
		out[len(out)-1].Current = true
	}
	return out
}

// listItem hides dotfiles, non-regular files and symlinks that do not
// resolve inside the root.
func (s *Server) listItem(dirPath string, e fs.DirEntry) (listItem, bool) {
	name := e.Name()
	if hidden(name) {
		return listItem{}, false
	}
	var (
		info fs.FileInfo
		err  error
	)
	if e.Type()&fs.ModeSymlink != 0 {
		target := rootName(path.Join(dirPath, name))
		if !s.visible(target, nil) {
			return listItem{}, false
		}
		info, err = s.root.Stat(target)
	} else {
		info, err = e.Info()
	}
	if err != nil {
		return listItem{}, false
	}

	mod := info.ModTime().UTC()
	item := listItem{
		Name:    name,
		Key:     strings.ToLower(name),
		Href:    escapePath(path.Join(dirPath, name)),
		ModTime: mod.Format("Jan 2, 2006 15:04") + " UTC",
		ModISO:  mod.Format(time.RFC3339),
		mod:     mod,
	}
	switch {
	case info.IsDir():
		item.IsDir = true
		item.Href += "/"
		item.Kind = "folder"
		item.Size = "—"
	case info.Mode().IsRegular():
		item.Kind = kindOf(name)
		item.size = info.Size()
		item.Size = formatSize(item.size)
	default:
		return listItem{}, false
	}
	return item, true
}

var fileKinds = func() map[string]string {
	m := make(map[string]string)
	for kind, exts := range map[string]string{
		"image":   "jpg jpeg png gif webp svg bmp tif tiff heic heif avif ico",
		"video":   "mp4 m4v mkv mov avi webm wmv flv mpg mpeg",
		"audio":   "mp3 flac wav ogg oga opus m4a aac wma",
		"archive": "zip rar 7z tar gz tgz bz2 xz zst iso dmg deb rpm apk",
		"doc":     "pdf doc docx odt rtf epub",
		"sheet":   "xls xlsx ods csv tsv",
		"slides":  "ppt pptx odp key",
		"code":    "go js ts py rb rs c h cpp hpp java kt swift sh php html css json yaml yml toml xml sql",
		"text":    "txt md log ini conf cfg",
	} {
		for _, ext := range strings.Fields(exts) {
			m["."+ext] = kind
		}
	}
	return m
}()

// kindOf picks the icon for a file name.
func kindOf(name string) string {
	return cmp.Or(fileKinds[strings.ToLower(path.Ext(name))], "file")
}

// escapePath percent-encodes a URL path so names containing '#', '?', '%'
// and the like produce working links.
func escapePath(p string) string {
	return (&url.URL{Path: p}).EscapedPath()
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
