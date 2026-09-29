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
	if versions != 1 || rules != 7 {
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
