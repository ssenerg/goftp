package server

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v3"

	"goftp/internal/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

var pages = template.Must(template.ParseFS(templateFS, "templates/*.html"))

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
	Path   string
	Parent string
	Items  []listItem
	Upload *uploadForm
}

type uploadForm struct {
	Action  string
	Replace bool
}

type listItem struct {
	Name    string
	Href    string
	Size    string
	ModTime string
	IsDir   bool
	key     string
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
	items := make([]listItem, 0, len(entries))
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
		} else if ok {
			items = append(items, item)
		}
	}
	slices.SortFunc(items, func(a, b listItem) int {
		if a.IsDir != b.IsDir {
			if a.IsDir {
				return -1
			}
			return 1
		}
		if n := strings.Compare(a.key, b.key); n != 0 {
			return n
		}
		return strings.Compare(a.Name, b.Name)
	})

	data := listing{page: s.page(c, "/"), Path: urlPath, Items: items}
	if urlPath != "/" {
		data.Title = path.Base(urlPath)
		data.Parent = escapePath(strings.TrimSuffix(path.Dir(urlPath), "/") + "/")
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

	item := listItem{
		Name:    name,
		Href:    escapePath(path.Join(dirPath, name)),
		ModTime: info.ModTime().Format("Jan 02, 2006 15:04"),
		key:     strings.ToLower(name),
	}
	switch {
	case info.IsDir():
		item.IsDir = true
		item.Href += "/"
		item.Size = "—"
	case info.Mode().IsRegular():
		item.Size = formatSize(info.Size())
	default:
		return listItem{}, false
	}
	return item, true
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
