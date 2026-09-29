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

## Uploads

Uploads are off by default and use their own key, so shared download links
never grant write access:

```sh
export GOFTP_UPLOAD_ENABLED=true GOFTP_UPLOAD_KEY="$(openssl rand -hex 24)"
```

- Browser: listing pages show an upload form (upload key and files).
- curl: `curl -T file.iso -H "Authorization: Bearer $GOFTP_UPLOAD_KEY" https://host/dir/`
  (or pass `?key=` in the URL, naming the file). Add `-H "If-None-Match: *"` to
  never replace an existing file.

The target directory must exist, and `upload.max_size` caps each file. While
a file is uploading, the lock file `.<name>.lock` hides it from listings and
downloads, and the data goes to a hidden `.goftp-*.part` file that is renamed
into place only once complete, so partial uploads are never visible. Other
tools can use the same convention: create `.<name>.lock` before writing
`<name>` and remove it afterwards. A crash can leave `.goftp-*.part` files
behind; they are safe to delete, and their locks are ignored and replaced by
the next upload of that name. Run one goftp instance per directory.

## Security notes

- Serve over HTTPS (`tls.*` settings or a TLS-terminating proxy): the key
  travels in the URL.
- Wrong keys are rate limited per client (`limiter.*`): once the budget is
  spent, further download attempts get 429 until the window ends. Behind a
  reverse proxy, set `server.proxy_header` and `server.trusted_proxies`,
  otherwise every client shares the proxy's budget.
- Symlinks are followed only when they use relative targets that stay inside
  the served directory and do not lead into a dotfile or dot-directory.

## Development

```sh
go test -race ./...
```
