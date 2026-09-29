// Package dbtest gives tests a private, migrated Postgres schema.
package dbtest

import (
	"context"
	"crypto/rand"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"goftp/internal/db"
)

// EnvURL names the variable holding the test database URL.
const EnvURL = "GOFTP_TEST_DATABASE_URL"

// Open returns a pool on a new schema of the database at $GOFTP_TEST_DATABASE_URL,
// and a URL for further connections to it. The test is skipped when the
// variable is unset.
func Open(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	base := os.Getenv(EnvURL)
	if base == "" {
		t.Skip(EnvURL + " is not set")
	}
	ctx := context.Background()
	schema := "test_" + strings.ToLower(rand.Text())
	exec := func(sql string) {
		conn, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE SCHEMA " + schema)
	t.Cleanup(func() { exec("DROP SCHEMA " + schema + " CASCADE") })

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	pool, err := db.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, u.String()
}
