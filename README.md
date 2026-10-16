# fauxy

A local HTTP/HTTPS proxy that answers selected requests with mocks declared in
YAML files and forwards everything else to the real servers.

It covers the "map local" use case of tools like Charles or Proxyman, but it is
configured with plain files, runs as a background daemon on macOS and Linux,
and is driven from the terminal.

```
app ──HTTP(S)_PROXY──▶ fauxy (127.0.0.1:8899)
                         ├─ HTTPS host with rules ─▶ decrypt with the local CA
                         │                             ├─ rule matches ─▶ mock response
                         │                             └─ no match ─────▶ real server
                         ├─ HTTPS host without rules ─▶ plain tunnel, never decrypted
                         └─ HTTP ─▶ same matching as above
CLI / TUI ◀── Unix socket (HTTP + JSON) ──▶ daemon
```

Only hosts that appear in enabled rules are decrypted. Everything else passes
through untouched, so fauxy can stay on all day without breaking other traffic.

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Writing rules](#writing-rules)
- [Changing the port](#changing-the-port)
- [Routing applications through fauxy](#routing-applications-through-fauxy)
- [Java and Spring Boot](#java-and-spring-boot)
- [HTTPS and the local CA](#https-and-the-local-ca)
- [Running as a service](#running-as-a-service)
- [Running in the foreground (testing and debugging)](#running-in-the-foreground-testing-and-debugging)
- [Command reference](#command-reference)
- [Terminal UI](#terminal-ui)
- [Files and environment variables](#files-and-environment-variables)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Development](#development)
- [Versioning](#versioning)
- [License](#license)

## Features

- Mock rules in YAML (or JSON): match on scheme, method, host (wildcards and
  ports), path patterns, query parameters and headers.
- Responses with status, headers, inline text, JSON, a file read on every
  request, and an artificial delay.
- Selective interception: HTTPS is decrypted only for hosts with enabled rules.
- Hot reload: saving a rule file applies it immediately; an invalid file keeps
  the previous rules and reports the error with file, line and column.
- Background daemon, launchd/systemd user service, terminal UI with live
  traffic, and runtime rule toggles.
- Helpers for curl, Node.js, Python and the JVM (`fauxy env`), including a
  Java truststore.

## Installation

Requirements:

- macOS or Linux.
- Rust 1.89 or newer to build. The repository declares its tools in
  `mise.toml` for [mise](https://mise.jdx.dev/) (Rust stable and
  cargo-llvm-cov); plain `rustup` works too.
- Optional: a JDK (for the Java truststore) and `sudo` on Linux (to trust the
  local CA system-wide).

Install from the repository:

```sh
cargo install --locked --git https://github.com/osrochabr/fauxy
```

Or from a local clone:

```sh
git clone https://github.com/osrochabr/fauxy
cd fauxy
cargo install --locked --path .
fauxy --version
```

The binary goes to `~/.cargo/bin`, which must be on your `PATH`.

## Quick start

```sh
fauxy init              # creates ~/.config/fauxy and the local CA
$EDITOR ~/.config/fauxy/mocks/my-api.yaml
fauxy check             # validates every file
fauxy ca install        # trusts the local CA for HTTPS (Linux: add --system, see below)
fauxy start             # starts the daemon in the background
eval "$(fauxy env)"     # routes this shell through the proxy
curl https://api.example.com/v1/login
```

A minimal rule file:

```yaml
# ~/.config/fauxy/mocks/my-api.yaml
host: api.example.com
rules:
  - name: login
    match:
      method: POST
      path: /v1/login
    respond:
      status: 200
      json: { token: abc123 }
```

`fauxy init` also writes `mocks/example.yaml`, disabled, with commented
examples. More examples live in [`examples/`](examples/):

```sh
fauxy --config examples/config.yaml check
```

fauxy runs one daemon per state directory, whatever `--config` says. To try
the examples while your regular daemon is running, give them their own state
directory (the example listens on port 8898):

```sh
export FAUXY_STATE_DIR="$HOME/.local/state/fauxy-example"
fauxy --config examples/config.yaml start
fauxy status
fauxy stop
unset FAUXY_STATE_DIR
```

## Writing rules

Rule files live in the directories listed in `mocks` (by default
`~/.config/fauxy/mocks`).

- `*.yaml` and `*.yml` files are read in alphabetical order. Hidden files are
  skipped.
- JSON rule files are accepted only when listed explicitly in `mocks`, so
  `.json` fixtures can sit next to the rules.
- The first enabled rule that matches a request wins. Requests without a
  matching rule go to the real server.

```yaml
enabled: true                 # false disables every rule of the file
host: api.example.com         # default host of the rules below
rules:
  - name: login               # unique across all files; defaults to <file stem>#<index>, e.g. my-api#1
    enabled: true
    match:
      method: [POST, PUT]     # one method or a list; omitted = any; "*" or ANY = any
      path: /v1/users/:id     # :name and * match one segment, ** any number
      query: { version: "2", token: "*" }   # "*" = present with any value
      headers: { X-Tenant: acme }           # header names are case-insensitive
      scheme: https           # optional: http or https
      # url: https://api.example.com/v1/login?version=2   shortcut for scheme+host+path+query
    respond:
      status: 200             # default 200
      headers: { X-Mocked-By: fauxy }
      json: { ok: true }      # or body: "text", or file: fixtures/response.json
      delay: 800ms            # humantime syntax: 250ms, 2s, 1m
```

| Field | Notes |
|---|---|
| `host` | Name only, without scheme or path. `*.example.com` matches subdomains but not `example.com` itself. A port (`localhost:8080`) must match too. Case-insensitive. |
| `path` | Must start with `/`. Trailing and repeated slashes are ignored. Without `path`, every path matches. Query strings belong in `query`. |
| `url` | Cannot be combined with `host`, `path` or `scheme`. Without a path it means `/`. Its query parameters must match exactly. |
| `json` | Serialized and sent as `application/json`. |
| `body` | Sent as `text/plain; charset=utf-8` unless `headers` sets `Content-Type`. |
| `file` | Relative to the rule file and read on every request (edit it without reloading). It must stay inside the rule file's directory, also through symbolic links. Content type guessed from the extension. |
| `delay` | Applied before answering. |

Only one of `body`, `json` and `file` may be set. Every mocked response carries
an `x-fauxy-rule` header with the rule name.

Check what would answer a request without sending it:

```sh
fauxy test POST https://api.example.com/v1/login -H "X-Tenant: acme"
```

### Global configuration

`~/.config/fauxy/config.yaml` (every key is optional):

```yaml
listen: 127.0.0.1:8899        # or just the port
mocks:
  - mocks                     # relative to this file; '~' is expanded
  - ~/projects/app/fauxy      # mocks versioned with a project
upstream:
  ca_files: []                # extra PEM CAs to validate real servers (private chains)
```

Changes to `listen` and `upstream` require `fauxy restart`; everything else is
reloaded automatically. Use `--config FILE` (or `FAUXY_CONFIG`) to run with a
project-specific configuration.

## Changing the port

fauxy listens on `127.0.0.1:8899` by default. The port is the `listen` setting
of `config.yaml`; `start`, `restart`, the user service, `env` and `check` all
read it from there.

`fauxy init --port <port>` writes it for you:

```sh
fauxy init --port 9000    # new setup: creates config.yaml with listen: 127.0.0.1:9000
fauxy init --port 9001    # existing setup: changes only the port of 'listen'
```

On an existing `config.yaml`, `--port` keeps the host of `listen` (for
example `0.0.0.0`), the comments and every other setting, and replaces the
file in one step. A file it cannot edit safely, a read-only file or a
symbolic link is reported and left unchanged: set `listen: <port>` in it by
hand (`--force` does not replace symbolic links either). The other
existing files are left alone (use `--force` to recreate them). With
`--config FILE` (or `FAUXY_CONFIG`), `init` works on that file and on a
`mocks` directory next to it.

A running daemon keeps its port until it restarts:

```sh
fauxy restart                                           # daemon started with fauxy start
launchctl kickstart -k gui/$(id -u)/dev.fauxy.daemon    # user service on macOS
systemctl --user restart fauxy-daemon                   # user service on Linux
```

Then update the clients that still use the old port:

- shells: run `eval "$(fauxy env)"` (or `eval "$(fauxy env --java)"`) again;
- IDE run configurations: paste the new `fauxy env --jvm-flags` output;
- browsers and system proxy settings: use the address shown by `fauxy status`.

When the port is taken, fauxy says so and shows how to find the program using
it (see [Troubleshooting](#troubleshooting)).

To try another port once, without touching `config.yaml`, use
`fauxy run --port <port>` (see
[Running in the foreground](#running-in-the-foreground-testing-and-debugging)).

## Routing applications through fauxy

`fauxy env` prints the variables most tools understand:

```sh
eval "$(fauxy env)"                 # bash/zsh
fauxy env --shell fish | source     # fish
eval "$(fauxy env --unset)"         # undo
```

| Variable | Used by |
|---|---|
| `HTTP_PROXY`, `HTTPS_PROXY` (and lowercase) | curl, wget, Go, Python `requests`, most CLIs |
| `FAUXY_PROXY` | The proxy URL alone, for your own scripts |
| `NO_PROXY` | Keeps `localhost` direct |
| `NODE_EXTRA_CA_CERTS` | Node.js (adds the fauxy CA) |
| `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` | OpenSSL-based tools and Python, pointing at a bundle with the system roots plus the fauxy CA |
| `JAVA_TOOL_OPTIONS` | Only with `--java`, see below |

Browsers use the system proxy settings: point them at the proxy address
(`127.0.0.1:8899` by default, shown by `fauxy status`) or use a proxy
extension. Firefox has its own certificate store; import the file printed
by `fauxy ca path` in its settings.

## Java and Spring Boot

The JVM ignores `HTTP_PROXY` and the system trust store. It needs proxy system
properties and a truststore containing the JDK roots plus the fauxy CA. fauxy
builds that truststore with the `keytool` of the JDK found in `--java-home`,
`JAVA_HOME`, `java` on the `PATH` or `/usr/libexec/java_home` (macOS).

For the current shell (`mvn spring-boot:run`, `./gradlew bootRun`, `java -jar`):

```sh
eval "$(fauxy env --java)"    # sets JAVA_TOOL_OPTIONS
```

For an IDE run configuration, paste the output of this command into the VM
options:

```sh
fauxy env --jvm-flags
# -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8899 -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8899
# -Djavax.net.ssl.trustStore=~/.local/state/fauxy/ca/java-truststore.p12
# -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12
```

Rebuild the truststore after switching JDKs: `fauxy ca java --java-home <dir>`.

Clients that use the JVM proxy settings work out of the box: `java.net.http.HttpClient`,
`HttpURLConnection` and therefore Spring's default `RestTemplate`. Some clients
ignore those settings and need explicit configuration, for example Apache
HttpClient built without `useSystemProperties()`. The test suite exercises
both JDK clients against a real JVM.

Remember that the mock must look like what the client expects: a library may
need a specific status (such as `201` for a creation) or specific fields in the
body. `fauxy logs` and the TUI show exactly what was answered.

## HTTPS and the local CA

`fauxy init` (or the first daemon start) creates a certificate authority in
`~/.local/state/fauxy/ca/`. The daemon signs a certificate for each
intercepted host on the fly. Clients must trust the CA:

```sh
fauxy ca install --dry-run    # shows the commands
fauxy ca install              # macOS: trusted for TLS in your login keychain
fauxy ca install --system     # Linux: system trust store, via sudo
fauxy ca uninstall            # removes the trust again
fauxy ca path                 # path of the certificate, for manual imports
```

On macOS the CA is trusted for TLS server authentication in your login
keychain only. On Linux the trust stores are system-wide
(`update-ca-certificates` on Debian, Ubuntu and Alpine, `update-ca-trust` on
Fedora and RHEL, p11-kit `trust` on Arch and others): every user and service
of the machine would trust a key that lives in your home directory, so fauxy
asks for `--system` to confirm. Without it, `fauxy env` and the Java
truststore cover command-line tools and the JVM.

Real servers are always validated with the system roots plus
`upstream.ca_files`; there is no option to skip that validation.

## Running as a service

```sh
fauxy service install     # starts now and at every login
fauxy service status
fauxy service uninstall
```

On macOS this is a launchd agent (`~/Library/LaunchAgents/dev.fauxy.daemon.plist`);
on Linux a `systemd --user` unit (`~/.config/systemd/user/fauxy-daemon.service`).
`fauxy service install` stops a daemon started with `fauxy start`, so the
service can take over. The service restarts fauxy when it crashes;
`fauxy stop` leaves it stopped until the next login. Use the service manager
to start or restart it, since `fauxy start`/`fauxy restart` would launch a
daemon that launchd/systemd does not supervise:
`launchctl kickstart -k gui/$(id -u)/dev.fauxy.daemon` on macOS,
`systemctl --user restart fauxy-daemon` on Linux. Do the same after upgrading
the binary.

## Running in the foreground (testing and debugging)

`fauxy run` runs the daemon in your terminal instead of in the background:
every request is logged as it happens, and `Ctrl-C` stops it.

```sh
fauxy run                       # same configuration as `fauxy start`
fauxy run --port 9100           # this run only listens on 9100
FAUXY_LOG=debug fauxy run       # verbose logs
fauxy run --no-watch            # ignore file changes (reload with `fauxy reload`)
fauxy run --log-file run.log    # log to a file; fatal errors still reach the terminal
```

`--port` replaces the port of `listen` for that run only; `config.yaml` is not
changed, so the next `fauxy start` uses the configured port again. While it
runs, `fauxy status`, `fauxy env` and `fauxy env --jvm-flags` report the port
in use, so clients can be pointed at it.

Only one daemon runs per state directory. Stop the background daemon first
(`fauxy stop`; a user service then stays stopped until the next login or until
you restart it with the service manager), or run a separate instance with its
own state directory:

```sh
FAUXY_STATE_DIR="$HOME/.local/state/fauxy-debug" fauxy run --port 9100
FAUXY_STATE_DIR="$HOME/.local/state/fauxy-debug" fauxy env --jvm-flags
```

The separate instance reads the same configuration and rules (point it
elsewhere with `FAUXY_CONFIG_DIR` or `--config`), but has its own local CA,
Java truststore and log. `fauxy env` with the same `FAUXY_STATE_DIR` points
clients at them; prefer that to `fauxy ca install`, because on Linux the
system store holds one fauxy CA at a time and installing this one would
replace your main CA. Keep state directories in a private location, not in
`/tmp`: whoever controls one controls the CA that your clients trust.

## Command reference

| Command | Description |
|---|---|
| `fauxy init [--force] [--port PORT]` | Create the configuration (or the `--config` file), an example file and the local CA; `--port` sets `listen` in it (see [Changing the port](#changing-the-port)) |
| `fauxy start` / `stop` / `restart` | Control the background daemon |
| `fauxy status` | Daemon status (exit code 3 when stopped) |
| `fauxy run [--port PORT] [--log-file F] [--no-watch]` | Run in the foreground; `--port` applies to that run only (see [Running in the foreground](#running-in-the-foreground-testing-and-debugging)) |
| `fauxy reload` | Reload the rules now |
| `fauxy logs [-f] [-n N]` | Daemon log, including every request (MOCK, PASS, TUNNEL, ERROR) |
| `fauxy rules [list\|enable NAME\|disable NAME]` | List rules or toggle them in memory until the daemon restarts |
| `fauxy check` | Validate the configuration |
| `fauxy test METHOD URL [-H "Name: value"]` | Show which rule would answer, without sending anything |
| `fauxy ca install [--dry-run] [--system]` / `ca uninstall [--dry-run]` | Trust or untrust the local CA (`--system` confirms a system-wide store, as on Linux) |
| `fauxy ca path` / `fauxy ca java [--java-home DIR]` | CA path / build the Java truststore |
| `fauxy env [--java\|--jvm-flags [--java-home DIR]\|--unset] [--shell fish]` | Environment variables for the proxy |
| `fauxy service install\|uninstall\|status` | User service (launchd or systemd) |
| `fauxy ui` | Terminal UI |

The global `--config FILE` option (or `FAUXY_CONFIG`) selects another
`config.yaml`. Commands that talk to the daemon (`status`, `stop`, `reload`,
`rules`, `logs`, `ui`) always address the daemon of the state directory.
Errors exit with 1, `fauxy status` exits with 3 when the daemon is stopped,
and invalid arguments exit with 2.

## Terminal UI

`fauxy ui` shows live traffic and the rules:

- **Traffic tab:** `Enter` shows the request details (headers and mocked body),
  `Esc` closes them or clears the filter, `/` filters, `f` toggles following
  new requests, `c` clears the list.
- **Rules tab:** `Space` or `Enter` enables or disables the selected rule, `e`
  opens its file in `$VISUAL`/`$EDITOR`.
- **Anywhere:** `Tab` or `1`/`2` switch tabs, arrows or `j`/`k` move,
  `PgUp`/`PgDn` jump, `Home`/`End` (or `g`/`G`) go to the first or last row,
  `r` reloads the configuration, `q` or `Ctrl-C` quits.

## Files and environment variables

| Path | Content |
|---|---|
| `~/.config/fauxy/config.yaml` | Global configuration |
| `~/.config/fauxy/mocks/` | Default rule directory |
| `~/.local/state/fauxy/` | Control socket, PID file and log (directory mode 0700) |
| `~/.local/state/fauxy/ca/` | CA certificate, private key (0600), bundle and Java truststore |

| Variable | Effect |
|---|---|
| `FAUXY_CONFIG` | Alternative `config.yaml` |
| `FAUXY_CONFIG_DIR`, `FAUXY_STATE_DIR` | Override the directories above |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME` | Honored when the variables above are not set |
| `FAUXY_LOG` | Log filter in `tracing` syntax (default `info,hudsucker=warn`) |

Logs larger than 10 MiB are rotated to `fauxy.log.1` when the daemon starts.

## Security

fauxy is a development tool that intercepts TLS, so keep these points in mind:

- **The CA private key can impersonate any website** for every program that
  trusts the CA. It never leaves `~/.local/state/fauxy/ca/` and is kept with
  mode 0600 (fauxy tightens it again if it becomes readable by others). Do not
  share it, and run `fauxy ca uninstall` when you stop using fauxy.
- **Rule files are trusted input.** A rule file decides which hosts are
  decrypted and what they answer, so only add mock directories you trust (for
  example, review the mocks of a cloned repository before listing them in
  `mocks`). Response files must stay inside the rule file's directory, and
  that is checked again on every request, through symbolic links.
- **Keep the proxy on loopback and on a single-user machine.** The proxy has
  no authentication: every local process, including other users' processes,
  can use it to reach hosts your machine can reach and to read your mocks.
  fauxy warns when `listen` is not a loopback address, since that turns it
  into an open proxy for the network.
- **Requests sent to fauxy directly** (not as a proxy, for example by a web
  page using DNS rebinding) are refused with `400`.
- **The control API is private:** the Unix socket lives in a 0700 directory,
  has mode 0600 and rejects connections from other users.
- **Decryption is selective:** only hosts with enabled rules are decrypted;
  everything else is tunneled without inspection.
- **Upstream TLS is always verified.**
- **Logs contain URLs** of the proxied requests, and the TUI shows request
  headers (which may include credentials). The log file is created with mode
  0600, and at most 8 KiB of headers is kept per request.
- **Terminal output is sanitized:** control characters and invisible
  formatting characters (such as bidirectional overrides) received from the
  network are replaced before `fauxy logs` and the TUI print them.
- **The state directory** must be a real directory owned by you: the daemon
  and the commands that read or create the local CA (`init`, `ca`, `env`)
  refuse a symbolic link or a directory owned by someone else, and the other
  commands only trust a control socket served by your own user. Keep it out of
  shared directories such as `/tmp`.
- `fauxy stop` only signals a process that still holds the PID file lock, so a
  stale PID file can never make it kill an unrelated process.

## Troubleshooting

- **Requests do not show up in `fauxy logs` or the TUI:** the application is
  not using the proxy. Check that the variables or JVM flags reached the
  process (`ps eww <pid>` on macOS, `/proc/<pid>/environ` on Linux). Processes
  started by an IDE do not inherit variables exported in a terminal.
- **Certificate errors on an intercepted host:** the client does not trust the
  fauxy CA. Run `fauxy ca install`, use `fauxy env` for Node.js/Python, or the
  Java truststore for the JVM.
- **The mock is served but the application fails:** the response does not have
  the shape the client expects (status code, fields). Compare with the real
  API and adjust the rule; `fauxy test` shows which rule answers.
- **`fauxy start` fails:** the error includes the last lines of the log. Common
  causes are an invalid rule file (`fauxy check`) or the port being in use.
- **"port N is already in use":** another program (or another fauxy) has the
  port. Find it with `lsof -nP -iTCP:<port> -sTCP:LISTEN` (macOS) or
  `ss -ltnp 'sport = :<port>'` (Linux), or move fauxy to another port with
  `fauxy init --port <port>` and restart it (`fauxy restart`, or the service
  commands in [Changing the port](#changing-the-port)).
- **"the control socket path ... is too long":** Unix sockets are limited to
  about 100 characters; set `FAUXY_STATE_DIR` (or `XDG_STATE_HOME`) to a
  shorter directory.
- **The service keeps restarting:** check `fauxy logs`; fatal startup errors
  are written there too.
- **More detail:** `FAUXY_LOG=debug fauxy run` runs in the foreground with
  verbose logs.

## Limitations

- Intercepted hosts are served over HTTP/1.1; clients fall back automatically.
- Applications that pin certificates reject interception by design.
- Firefox and the JVM use their own trust stores (see above).
- Request bodies are not recorded; response bodies are recorded only for mocks.
- The proxy does not authenticate its clients (see Security).
- Windows is not supported.

## Development

The toolchain and tools are declared in `mise.toml`:

```sh
mise install                                        # Rust stable + cargo-llvm-cov
mise exec -- cargo build
mise exec -- cargo test                             # unit + integration tests
mise exec -- cargo fmt --check
mise exec -- cargo clippy --all-targets -- -D warnings
mise exec -- sh scripts/coverage.sh                 # fails unless every line is covered
```

Without mise, use `rustup` and `cargo install --locked cargo-llvm-cov`. The
coverage run needs the `llvm-tools-preview` component
(`rustup component add llvm-tools-preview`).

There is no CI yet: run the commands above before pushing. Set
`FAUXY_REQUIRE_JDK=1` to make the Java test fail instead of being skipped when
no JDK is found.

### Layout

| Module | Responsibility |
|---|---|
| `cli` | Argument parsing (clap) and command implementations |
| `config` | YAML schema, loading, validation and `fauxy init` templates |
| `rules` | Host/path patterns, request matching and mock responses |
| `proxy` | hudsucker handler: mocks, forwarding and traffic events |
| `daemon` | Daemon lifecycle, hot reload, PID file lock, logging, user service |
| `control` | Control API over the Unix socket (server and client) |
| `tls` | Local CA, system trust store commands, upstream TLS configuration |
| `java`, `envvars` | Java truststore and JVM flags; shell variables |
| `tui` | Terminal UI (state, rendering and event loop) |
| `state`, `events` | Shared runtime state and the in-memory traffic log |
| `sys` | The only module with `unsafe` (a few POSIX calls) |

### Tests

- Unit tests live next to the code (`#[cfg(test)]` modules).
- `tests/proxy.rs` runs the proxy in-process against local HTTP/HTTPS
  upstreams; `tests/daemon.rs` covers the daemon and the control API;
  `tests/cli.rs` runs the real binary, including a pseudo-terminal for the TUI;
  `tests/java.rs` calls the proxy from a real JVM when a JDK 11+ is available.
- System integrations never touch the machine: the tests put fake `security`,
  `sudo`, `launchctl`, `systemctl` and `keytool` executables first on the
  `PATH` and use temporary `HOME` and state directories.
- Line coverage is 100% (`scripts/coverage.sh`). The script merges every test
  binary; the summary table of `cargo llvm-cov` counts each instantiation of a
  generic function separately and can show a few lines that other binaries do
  execute.

To check Linux from macOS, run the suite in a container as a regular user:

```sh
docker run --rm -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/tmp/target rust:1-bookworm \
  sh -c 'useradd -m dev && chown -R dev /usr/local/cargo && su dev -c "PATH=$PATH cargo test --locked"'
```

Running as a regular user matters: some tests check permission errors, which
root never gets. The image must include `ca-certificates` (the Rust images
do).

### Conventions

- `cargo fmt` and `cargo clippy -D warnings` must pass; `unsafe` is denied
  outside `src/sys.rs`.
- User-facing messages are lowercase, without trailing periods, and explain
  how to fix the problem.
- Keep comments for what the code cannot say by itself.

## Versioning

fauxy follows [Semantic Versioning](https://semver.org/). Changes are listed in
[CHANGELOG.md](CHANGELOG.md). To release a version: update `version` in
`Cargo.toml` (and `Cargo.lock`, with `cargo build`), move the `Unreleased`
notes to a new section in the changelog, commit, tag it as `vX.Y.Z` and push
with `git push --follow-tags`.

## License

[MIT](LICENSE)
