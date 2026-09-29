package db_test

import (
	"context"
	"sync"
	"testing"

	"goftp/internal/db"
	"goftp/internal/db/dbtest"
)

func TestMigrateIsIdempotentAndSerialized(t *testing.T) {
	pool, _ := dbtest.Open(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() { errs <- db.Migrate(ctx, pool) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var versions, users int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if versions != 1 || users != 0 {
		t.Errorf("%d migrations recorded, %d users", versions, users)
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
