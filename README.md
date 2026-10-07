# server-init

TUI tool for the initial setup and hardening of a fresh Debian 12+ / Ubuntu 24.04+ server.
Single static binary, runs as root, nothing is changed before you confirm the summary.

> Work in progress. The full documentation (install, modules, files, rollback) follows with the modules.

## Build

```bash
go build -o server-init ./cmd/server-init
```

## Development

```bash
go test ./...
golangci-lint run ./...
```
