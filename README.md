# goftp

A small resumable file server built on [Fiber v3](https://gofiber.io), with
[Viper](https://github.com/spf13/viper) configuration,
[Zap](https://github.com/uber-go/zap) logging, and users stored in
Postgres whose access is decided by [Casbin](https://casbin.org) policies.

- Users sign in with a password; roles decide what they may do.
- Range (single and multipart), `If-Range`, `If-None-Match` and
  `If-Modified-Since` are supported, so downloads can be resumed.
- Uploads never expose partial files (see [Uploads](#uploads)).
- Dotfiles are never listed or served. Paths are resolved with `os.Root`, so
  requests and symlinks cannot escape the served directory.

## Quick start with Docker Compose

```sh
cp .env.example .env && chmod 600 .env   # set POSTGRES_PASSWORD, e.g. $(openssl rand -hex 24)
docker compose up -d --build
docker compose exec goftp goftp user add alice --role superadmin
```

`user add` prints a temporary password. Open http://localhost:8080, sign in
and choose a new password. The database lives in the `pgdata` volume, the
files in the `files` volume, unless `.env` names a directory to serve:

```sh
GOFTP_DATA=/mnt/storage/shared   # e.g. a disk, mounted before goftp starts
GOFTP_RUN_AS=1000:1000           # its owner (see `id`), so uploads can write
```

The port is only published on 127.0.0.1: put a TLS-terminating reverse
proxy in front and set `GOFTP_PROXY_HEADER=X-Forwarded-For` and
`GOFTP_TRUSTED_PROXIES` in `.env` (see [`.env.example`](.env.example)), or
let goftp serve HTTPS itself with `GOFTP_TLS_DIR`, `GOFTP_TLS_CERT` and
`GOFTP_TLS_KEY`, then set `GOFTP_BIND=0.0.0.0`.

## Users and roles

Sign-up happens on the command line, which needs access to the database:

```sh
goftp user add bob --role operator   # prints a temporary password
goftp user list
goftp user passwd bob                # new temporary password, ends bob's sessions
goftp user role bob admin
goftp user delete bob
```

New and reset passwords are temporary: after signing in, users can do
nothing but choose their own password (at least 12 characters), which ends
all their other sessions.

| Role         | May                                                          |
|--------------|--------------------------------------------------------------|
| `user`       | list directories and download (`read`)                       |
| `operator`   | also upload new files and create folders (`write`)           |
| `admin`      | also replace existing files (`overwrite`)                    |
| `superadmin` | every action (`*`)                                           |

These are Casbin rules on URL paths, kept in the `casbin_rule` table and
editable while the server runs (servers reload them within a moment):

```sh
goftp policy list
goftp policy add anonymous '/public/*' read   # public downloads, no sign-in
goftp policy add user:bob '/bob/*' write      # bob may upload into /bob/
goftp policy remove anonymous '/public/*' read
```

`"/docs/*"` covers `/docs/` and everything below it; `"/docs/"` alone is
just that listing. Listings only show what the visitor may open. Signed-in
users may always do what anonymous visitors may. A symlink never grants
more than the rules of where it leads: visitors need the rights for both
the path they use and the path the link points to.

## Running without Docker

```sh
export GOFTP_DATABASE_URL="postgres://goftp:secret@localhost:5432/goftp"
goftp user add alice --role superadmin
goftp --dir /srv/files --addr :8080       # same as: goftp serve ...
```

The schema is created or upgraded on startup (`goftp migrate` does just
that). Every setting can also come from a config file (`--config`, see
[`config.example.yaml`](config.example.yaml)) or a `GOFTP_*` environment
variable (`log.level` → `GOFTP_LOG_LEVEL`). Priority: flags > environment >
config file > defaults. The standard `PG*` variables (e.g. `PGPASSWORD`)
work as well.

## Clients

Browsers get a sign-in form. Other clients exchange credentials for a
session token and send it as a bearer token:

```sh
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"..."}' https://host/.auth/login
# {"token":"...","expires_at":"...","must_change_password":false}
curl -C - -O -H "Authorization: Bearer $TOKEN" https://host/dir/file.iso
```

A temporary password is changed with `POST /.auth/password`
(`{"current_password":"...","new_password":"..."}`), which returns a new
token. `POST /.auth/logout` ends the session. Sessions last
`auth.session_ttl` (12h).

## Uploads

- Browser: users who may upload into a folder can drop files anywhere on its
  page, or choose them, and watch each upload's progress. Existing files
  are only replaced when "Replace files that already exist" is ticked.
- curl: `curl -T file.iso -H "Authorization: Bearer $TOKEN" https://host/dir/`.
  PUT replaces existing files unless `-H "If-None-Match: *"` is given, and
  needs a Content-Length.

The target directory must exist, and `upload.max_size` caps each file.
Users who may upload new files into a folder (`write`) can also create
folders in it, with the "New folder" button or
`curl -d folder=photos -H "Authorization: Bearer $TOKEN" https://host/dir/`.

Partial uploads are never listed or served. While `<name>` is uploaded, the
lock file `.<name>.lock` keeps other uploads of it out, and the data goes to
a hidden `.goftp-*.part` file that is renamed into place only once complete;
until then the previous version, if any, stays available. Other tools can
hide files they write in place the same way: create `.<name>.lock` before
writing `<name>` and delete it afterwards (such locks are always honored;
a locked folder is hidden with everything in it).
A running upload refreshes its lock every 15 seconds; a lock left behind by
a goftp that stopped (crash, restart) is taken over by the next upload of
that name once it is a minute old, and removed with its temp file when
goftp starts again.

## Security notes

- Serve over HTTPS: passwords and session tokens travel with every sign-in
  and request. Over HTTPS (served by goftp, or by a trusted proxy that
  sends `X-Forwarded-Proto`) the session cookie is `Secure` and `__Host-`
  prefixed, and HSTS is sent.
- Passwords are hashed with Argon2id; only SHA-256 hashes of session tokens
  are stored.
- Failed sign-ins (and wrong current passwords) are rate limited per client
  (`limiter.*`), and each user can sign in at most 30 times a minute.
  Behind a reverse proxy, set `server.proxy_header` (`X-Forwarded-For`)
  and `server.trusted_proxies`, otherwise every client shares the proxy's
  budget and the server cannot tell that requests arrived over HTTPS;
  goftp logs a warning when it sees proxy headers it does not trust.
- Cross-site form posts and uploads are refused (`Sec-Fetch-Site`/`Origin`
  checks, `SameSite=Lax` cookies).
- Concurrent connections are capped to fit the open file limit. When
  clients connect directly rather than through a proxy, also cap what one
  client may hold with `server.max_conns_per_ip` (`GOFTP_MAX_CONNS_PER_IP`).
- Symlinks are followed only when they use relative targets that stay inside
  the served directory, do not lead into a dotfile or dot-directory, and
  lead where the visitor may go anyway.

## Troubleshooting

"Wrong username or password" at sign-in: `docker compose logs goftp | grep
"login failed"` shows whether the name matched no user or the password was
wrong (names that match no user are not logged: they are sometimes
passwords typed into the wrong field). `goftp user list` shows the users, and
`goftp user passwd NAME` gives one a new temporary password (temporary
passwords ignore case and surrounding spaces).

## Development

```sh
go test -race ./...
# Postgres-backed tests run when a database is given:
GOFTP_TEST_DATABASE_URL="postgres://postgres:secret@localhost/goftp_test" go test ./...
```

[CI](.github/workflows/ci.yml) runs these with Postgres on every pull request,
along with gofmt, `go vet`, builds for Windows, macOS and FreeBSD,
[govulncheck](https://go.dev/doc/security/vuln/) (also weekly) and a build
of the Docker image.
