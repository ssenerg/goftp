package server

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v3"
)

//go:embed listing.html
var listingHTML string

var listingTmpl = template.Must(template.New("listing").Parse(listingHTML))

type listing struct {
	Title  string
	Path   string
	Parent string
	Items  []listItem
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
	items := make([]listItem, 0, len(entries))
	for _, e := range entries {
		if item, ok := s.listItem(urlPath, e); ok {
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

	data := listing{Title: "/", Path: urlPath, Items: items}
	if urlPath != "/" {
		data.Title = path.Base(urlPath)
		data.Parent = escapePath(strings.TrimSuffix(path.Dir(urlPath), "/") + "/")
	}
	var buf bytes.Buffer
	if err := listingTmpl.Execute(&buf, data); err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	c.Set(fiber.HeaderCacheControl, "no-cache")
	return c.Send(buf.Bytes())
}

// listItem hides dotfiles, non-regular files and symlinks that do not
// resolve inside the root.
func (s *Server) listItem(dirPath string, e fs.DirEntry) (listItem, bool) {
	name := e.Name()
	if strings.HasPrefix(name, ".") {
		return listItem{}, false
	}
	var (
		info fs.FileInfo
		err  error
	)
	if e.Type()&fs.ModeSymlink != 0 {
		info, err = s.root.Stat(rootName(path.Join(dirPath, name)))
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
