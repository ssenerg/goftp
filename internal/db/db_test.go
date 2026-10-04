package db_test

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"goftp/internal/db"
	"goftp/internal/db/dbtest"
)

// Servers starting together must not run the same migration twice.
func TestConcurrentMigrations(t *testing.T) {
	url := dbtest.Schema(t)
	ctx := context.Background()
	var pools []*pgxpool.Pool
	for range 4 {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		if err := pool.Ping(ctx); err != nil {
			t.Fatal(err)
		}
		pools = append(pools, pool)
	}

	start := make(chan struct{})
	errs := make(chan error, len(pools))
	var wg sync.WaitGroup
	for _, pool := range pools {
		wg.Go(func() {
			<-start
			errs <- db.Migrate(ctx, pool)
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Migrate(ctx, pools[0]); err != nil {
		t.Fatalf("migrating again: %v", err)
	}
	var versions, rules int
	if err := pools[0].QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if err := pools[0].QueryRow(ctx, "SELECT count(*) FROM casbin_rule").Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if versions != 2 || rules != 8 {
		t.Errorf("%d migrations recorded, %d rules seeded", versions, rules)
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := db.Open(context.Background(), "postgres://%zz"); err == nil {
		t.Error("bad URL accepted")
	}
	if _, err := db.Open(context.Background(), "postgres://nobody@127.0.0.1:1/x?connect_timeout=1"); err == nil {
		t.Error("unreachable database accepted")
	}
}

// Admins get the delete action where their rule is still the default one.
func TestDeleteMigration(t *testing.T) {
	pool, _ := dbtest.Open(t)
	ctx := context.Background()
	adminDeletes := func() bool {
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM casbin_rule WHERE ptype = 'p' AND v0 = 'admin' AND v2 = 'delete'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	rerun := func(sql string) {
		t.Helper()
		for _, stmt := range []string{sql, "DELETE FROM casbin_rule WHERE v2 = 'delete'", "DELETE FROM schema_migrations WHERE version = 2"} {
			if _, err := pool.Exec(ctx, stmt); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.Migrate(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}
	if !adminDeletes() {
		t.Fatal("new installs: admins may not delete")
	}
	rerun("SELECT 1")
	if !adminDeletes() {
		t.Error("default rules: admins may not delete")
	}
	rerun("DELETE FROM casbin_rule WHERE v0 = 'admin' AND v2 = 'overwrite'")
	if adminDeletes() {
		t.Error("changed rules: admins were given delete")
	}
}
