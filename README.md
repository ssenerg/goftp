# goftp

A small resumable file server built on [Fiber v3](https://gofiber.io), with
[Viper](https://github.com/spf13/viper) configuration and
[Zap](https://github.com/uber-go/zap) logging.

- Directory listings are public; file downloads require the access key in a
  query parameter: `https://host/path/file.iso?key=<SECURE_KEY>`.
- Range (single and multipart), `If-Range`, `If-None-Match` and
  `If-Modified-Since` are supported, so downloads can be resumed.
- Dotfiles are never listed or served. Paths are resolved with `os.Root`, so
  requests and symlinks cannot escape the served directory.

## Usage

```sh
export SECURE_KEY="$(openssl rand -hex 24)"   # at least 16 characters
go run . --dir /srv/files --addr :8080
```

Flags: `--config`, `--dir`, `--addr`, `--query`. Every setting can also come
from a config file (see [`config.example.yaml`](config.example.yaml)) or a
`GOFTP_*` environment variable (`log.level` → `GOFTP_LOG_LEVEL`). Priority:
flags > environment > config file > defaults. The key is read from
`GOFTP_SECURE_KEY` or `SECURE_KEY`; it is intentionally not a flag, since
command lines are visible to other local users.

## Security notes

- Serve over HTTPS (`tls.*` settings or a TLS-terminating proxy): the key
  travels in the URL.
- Clients are blocked for a while after too many failed (4xx) requests
  (`limiter.*`), which stops key guessing. Behind a reverse proxy, set
  `server.proxy_header` and `server.trusted_proxies`, otherwise every client
  shares the proxy's budget.
- Symlinks are followed only when they use relative targets that stay inside
  the served directory and do not lead into a dotfile or dot-directory.

## Development

```sh
go test -race ./...
```
