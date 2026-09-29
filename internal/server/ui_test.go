package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"goftp/internal/auth"
)

// The only script the CSP admits is the one the pages embed.
func TestScriptMatchesCSP(t *testing.T) {
	f := newFixture(t)
	for target, visitor := range map[string]*fixture{"/": f, "/missing": f, loginPath: f.as("")} {
		resp, body := visitor.do(t, "GET", target, "Accept", "text/html")
		scripts := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllStringSubmatch(body, -1)
		if len(scripts) != 1 {
			t.Fatalf("%s: %d scripts", target, len(scripts))
		}
		sum := sha256.Sum256([]byte(scripts[0][1]))
		want := "script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "';"
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, want) || !strings.Contains(csp, "connect-src 'self'") {
			t.Errorf("%s: CSP %q lacks %q", target, csp, want)
		}
	}
}

func TestListingSortAndKinds(t *testing.T) {
	f := newFixture(t)
	f.write(t, "b-small.txt", "1")
	f.write(t, "a-big.MP4", strings.Repeat("x", 3000))
	f.write(t, "c-mid.tar.gz", strings.Repeat("x", 200))
	f.write(t, "zdir/x", "x")

	order := func(body string) []string {
		var names []string
		for _, m := range regexp.MustCompile(`<tr data-name="([^"]+)"`).FindAllStringSubmatch(body, -1) {
			names = append(names, m[1])
		}
		return names
	}
	for query, want := range map[string]string{
		"":                       "zdir a-big.mp4 b-small.txt c-mid.tar.gz",
		"?sort=size":             "zdir b-small.txt c-mid.tar.gz a-big.mp4",
		"?sort=size&order=desc":  "zdir a-big.mp4 c-mid.tar.gz b-small.txt",
		"?sort=name&order=desc":  "zdir c-mid.tar.gz b-small.txt a-big.mp4",
		"?sort=bogus&order=nope": "zdir a-big.mp4 b-small.txt c-mid.tar.gz",
	} {
		_, body := f.do(t, "GET", "/"+query)
		if got := strings.Join(order(body), " "); got != want {
			t.Errorf("%q: order %q, want %q", query, got, want)
		}
	}

	_, body := f.do(t, "GET", "/?sort=size")
	for _, want := range []string{
		`<th class="num" aria-sort="ascending"><a href="?sort=size&amp;order=desc">Size</a>`,
		`<th aria-sort="none"><a href="?sort=name">Name</a>`,
		`k-video" aria-hidden="true"><use href="#i-video"/>`,
		`k-archive" aria-hidden="true"><use href="#i-archive"/>`,
		`k-folder" aria-hidden="true"><use href="#i-folder"/>`,
		`<time datetime="`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}
}

func TestListingNotices(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "a")
	if _, body := f.do(t, "GET", "/?uploaded=2"); !strings.Contains(body, "Uploaded 2 files.") {
		t.Error("no upload confirmation")
	}
	if _, body := f.do(t, "GET", "/?uploaded=x"); strings.Contains(body, "Uploaded") {
		t.Error("bogus upload confirmation")
	}
	// Users who cannot upload see why the form is missing.
	_, body := f.as("user").do(t, "GET", "/")
	if !strings.Contains(body, "View only") || strings.Contains(body, `id="upload"`) {
		t.Error("user's listing lacks the view-only hint or offers uploads")
	}
	if _, body := f.as("operator").do(t, "GET", "/"); strings.Contains(body, "View only") {
		t.Error("operator's listing says view only")
	}
}

// Browsers get error pages; other clients plain text.
func TestErrorPages(t *testing.T) {
	f := newFixture(t)
	f.write(t, "sub/a.txt", "a")

	resp, body := f.do(t, "GET", "/sub/missing.txt", "Accept", "text/html")
	expectStatus(t, resp, http.StatusNotFound)
	for _, want := range []string{`<div class="code">404</div>`, "<h1>Not Found</h1>", `<a class="btn" href="/sub/">Back to the folder</a>`, "Signed in as"} {
		if !strings.Contains(body, want) {
			t.Errorf("404 page lacks %s", want)
		}
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("404 page headers %v", resp.Header)
	}
	if resp, body := f.do(t, "GET", "/sub/missing.txt"); body != "Not Found" || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("plain 404: %q", body)
	}

	// A failed form upload names the files stored before the failure.
	form, ctype := multipartForm(t,
		formPart{field: "file", filename: "b.txt", content: "b"},
		formPart{field: "file", filename: "a.txt", content: "changed"},
	)
	resp, body = f.send(t, "POST", "/sub/", form, "Content-Type", ctype, "Accept", "text/html")
	expectStatus(t, resp, http.StatusConflict)
	for _, want := range []string{"<h1>Conflict</h1>", "Stored before the error: b.txt", `href="/sub/">Back to the folder`} {
		if !strings.Contains(body, want) {
			t.Errorf("409 page lacks %s", want)
		}
	}

	// Anonymous form posts are offered the sign-in page.
	form, ctype = multipartForm(t, formPart{field: "file", filename: "c.txt", content: "c"})
	resp, body = f.as("").send(t, "POST", "/sub/", form, "Content-Type", ctype, "Accept", "text/html")
	expectStatus(t, resp, http.StatusUnauthorized)
	if !strings.Contains(body, `href="/.auth/login?next=%2fsub%2f">Sign in</a>`) {
		t.Error("401 page lacks the sign-in link")
	}
}

func TestPasswordPageModes(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	_, body := f.as("user").do(t, "GET", passwordPath+"?next=/docs/")
	for _, want := range []string{"<h1>Change password</h1>", `<a href="/docs/">Cancel</a>`, "Current password"} {
		if !strings.Contains(body, want) {
			t.Errorf("password page lacks %s", want)
		}
	}
	temp, err := ta.svc.CreateUser(t.Context(), "fresh", auth.Roles[3])
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ta.svc.Login(t.Context(), "fresh", temp)
	if err != nil {
		t.Fatal(err)
	}
	_, body = f.do(t, "GET", passwordPath, "Authorization", "Bearer "+sess.Token)
	for _, want := range []string{"<h1>Choose your password</h1>", "Temporary password", "Save and continue"} {
		if !strings.Contains(body, want) {
			t.Errorf("forced password page lacks %s", want)
		}
	}
	if strings.Contains(body, "Cancel") {
		t.Error("forced password page offers to cancel")
	}
}

func TestSummary(t *testing.T) {
	for _, tc := range []struct {
		dirs, files int
		total       int64
		want        string
	}{
		{0, 0, 0, "Empty folder"},
		{1, 0, 0, "1 folder"},
		{0, 1, 5, "1 file · 5 B"},
		{3, 10, 3 << 20, "3 folders · 10 files · 3.0 MiB"},
	} {
		if got := summary(tc.dirs, tc.files, tc.total); got != tc.want {
			t.Errorf("summary(%d, %d, %d) = %q, want %q", tc.dirs, tc.files, tc.total, got, tc.want)
		}
	}
}
