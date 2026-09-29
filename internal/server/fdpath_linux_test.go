package server

import (
	"os"
	"path/filepath"
	"testing"
)

// A symlink swapped between open and check must not make a hidden file
// look visible.
func TestVisibleChecksOpenedFile(t *testing.T) {
	f := newFixture(t)
	f.write(t, ".git/config", "secret")
	f.write(t, "real/config", "public")
	link := filepath.Join(f.dir, "pub")
	if err := os.Symlink(".git", link); err != nil {
		t.Fatal(err)
	}
	fh, err := f.srv.open("/pub/config")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", link); err != nil {
		t.Fatal(err)
	}
	if !f.srv.visible("pub/config", nil) {
		t.Fatal("setup: the swapped link should resolve to a visible path")
	}
	if f.srv.visible("pub/config", fh) {
		t.Fatal("opened hidden file judged by its re-resolved name")
	}
}
