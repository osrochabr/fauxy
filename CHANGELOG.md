# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `fauxy init --port <port>` sets the proxy port: it creates `config.yaml`
  with that port, or updates the port of `listen` in an existing one, keeping
  its host, comments and other settings. The file is replaced in one step;
  symbolic links, read-only files and files it cannot edit safely are left
  for a manual edit.
- `fauxy run --port <port>` listens on another port for that run only,
  without changing `config.yaml`, for testing and debugging.

### Changed

- A port already in use is reported as such, with the command that finds the
  program using it (`lsof` on macOS, `ss` on Linux) and how to choose another
  port.
- `fauxy init` honors `--config` (and `FAUXY_CONFIG`) instead of ignoring it:
  it creates or updates that file and a `mocks` directory next to it. It also
  shows the configuration warnings, such as a non-loopback `listen`, and
  `--force` no longer writes through symbolic links.
- Fatal errors of `fauxy run` are no longer written twice to the log, and
  `FAUXY_LOG` cannot hide them. With `--log-file` they also go to stderr,
  unless stderr is that same file.
- "fauxy is already running" explains how to run another instance.

### Fixed

- Commands whose output goes to a closed pipe (such as `fauxy logs | head`)
  end quietly instead of panicking.

### Security

- Commands that read or create the local CA (`env`, `ca`, `init`) refuse a
  state directory that is a symbolic link or belongs to another user, as the
  daemon already did. Before, `fauxy env` could point clients at a proxy and
  a CA planted by another user in a shared directory.
- The CLI only trusts a control socket served by its own user.
- The documentation no longer suggests state directories under `/tmp`.

## [0.1.0] - 2026-10-16

First release.

### Added

- HTTP/HTTPS proxy that answers matching requests with mocks and forwards
  everything else to the real servers. Only hosts with enabled rules are
  decrypted; other HTTPS connections are tunneled untouched.
- Mock rules in YAML (or JSON) files: match on scheme, method, host
  (with `*.` wildcards and ports), path patterns (`:param`, `*`, `**`), query
  parameters and headers; respond with a status, headers, an inline body,
  JSON, a file read at request time and an optional delay.
- Hot reload of the rule files, keeping the previous rules when a file is
  invalid, and `fauxy check` / `fauxy test` to validate and explain rules.
- Background daemon (`start`, `stop`, `restart`, `status`, `reload`, `logs`),
  user service for launchd (macOS) and systemd (Linux), and a terminal UI with
  live traffic and runtime rule toggles.
- Local CA management (`fauxy ca`), system trust store integration on macOS,
  Debian, Fedora and p11-kit based distributions, a CA bundle for tools that
  replace their trust store, and a Java truststore with JVM flags
  (`fauxy env --java`, `fauxy env --jvm-flags`).

### Security

- The control socket and the state directory are private to the user, and
  connections from other users are rejected.
- The CA private key is kept with mode 0600 and tightened if it became
  readable by others.
- `fauxy stop` only signals a PID whose PID file is still locked by a live
  daemon, so a stale PID file never leads to signaling an unrelated process.
- Upstream certificates are always validated.
- Control and invisible formatting characters received from the network are
  neutralized before `fauxy logs` and the terminal UI print them.
- Listening on a non-loopback address produces a warning, since it exposes
  the proxy to other machines.
- Response files must resolve inside the directory of their rule file, checked
  when loading and on every request.
- Requests sent to the proxy directly (not as a proxy) are refused, which
  blocks DNS rebinding attempts from web pages.
- On Linux, trusting the CA in the system-wide store requires `--system`; on
  macOS the CA is trusted for TLS only, in the user's login keychain.
- The state directory must be a real directory owned by the user.
- At most 8 KiB of headers is kept per recorded request.

[Unreleased]: https://github.com/osrochabr/fauxy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/osrochabr/fauxy/releases/tag/v0.1.0
