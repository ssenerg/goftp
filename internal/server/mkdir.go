package server

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"net/url"
	"path"
	"strings"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

const badFolderName = "Folder names cannot be empty or very long, start with a dot, or contain / or \\."

// mkdir creates the folder named by the form field "folder" in the
// directory at urlPath, e.g. curl -d folder=photos https://host/dir/
func (s *Server) mkdir(c fiber.Ctx, urlPath string) error {
	// Like uploads, this spares reading the body of visitors who may not
	// create anything here.
	mayCreate := func(obj string) (bool, error) { return s.allowed(c, obj, auth.ActWrite) }
	if ok, err := mayCreate(object(urlPath, true)); err != nil {
		return err
	} else if !ok {
		return s.deny(c)
	}
	form, _, err := s.readForm(c)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(form["folder"])
	if !validName(name) {
		return s.sendError(c, fiber.ErrBadRequest, badFolderName)
	}
	target := path.Join(urlPath, name)
	if ok, err := mayCreate(object(target, true)); err != nil {
		return err
	} else if !ok {
		return s.deny(c)
	}
	dir, realDir, err := s.uploadDir(urlPath)
	if err != nil {
		return err
	}
	defer dir.Close()
	// Through symlinks, the rules of the real folder apply as well.
	if realTarget := path.Join(realDir, name); realTarget != target {
		if ok, err := mayCreate(object(realTarget, true)); err != nil {
			return err
		} else if !ok {
			return s.deny(c)
		}
	}

	// The lock keeps uploads of the same name out meanwhile.
	release, err := s.acquireLock(dir, name, tempPrefix+rand.Text()+tempSuffix)
	if err != nil {
		return err
	}
	defer release()
	if err := dir.Mkdir(name, 0o755); errors.Is(err, fs.ErrExist) {
		return fiber.ErrConflict
	} else if err != nil {
		return s.uploadError(&requestBody{}, err)
	}
	syncDir(dir)

	user := auth.Anonymous
	if u := userOf(c); u != nil {
		user = u.Username
	}
	s.log.Info("mkdir", zap.String("ip", c.IP()), zap.String("user", user), zap.String("path", target))
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		c.Location(escapePath(target + "/"))
		return c.SendStatus(fiber.StatusCreated)
	}
	return s.redirect(c, escapePath(object(urlPath, true))+"?created="+url.QueryEscape(name))
}
