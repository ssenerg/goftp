package db

import (
	"testing"
	"testing/fstest"
)

func TestMigrationFiles(t *testing.T) {
	files := func(names ...string) fstest.MapFS {
		fsys := fstest.MapFS{}
		for _, n := range names {
			fsys["migrations/"+n] = &fstest.MapFile{}
		}
		return fsys
	}
	got, err := migrationFiles(files("10_c.sql", "9_b.sql", "002_a.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].name != "002_a.sql" || got[1].version != 9 || got[2].version != 10 {
		t.Errorf("order %v", got)
	}
	for _, bad := range []fstest.MapFS{files("2_a.sql", "002_b.sql"), files("x_a.sql"), files("0_a.sql")} {
		if _, err := migrationFiles(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	if m, err := migrationFiles(migrations); err != nil || len(m) == 0 || m[0].version != 1 {
		t.Errorf("embedded migrations %v: %v", m, err)
	}
}
