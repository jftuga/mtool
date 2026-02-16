# CLAUDE.md — mtool development guide

## Project overview

`mtool` is a multi-tool CLI utility written in Go using **only standard library packages**. No third-party imports are allowed. This is a hard constraint — every feature must be implemented with what the Go stdlib provides. The project currently uses 91 unique standard library packages.

## Architecture

### File structure

```
main.go                     # ~110-line thin dispatcher, routes subcommands
cmd_<name>.go               # One per subcommand: flag parsing + calls internal package
cmd_<name>_test.go          # Tests for each subcommand
testhelpers_test.go         # Shared test utilities (captureStdout, writeTestFile, assertContains)
internal/
  shared/shared.go          # Shared utilities: FormatSize, ReadInput, CryptoRandIntn
  <package>/                # One package per subcommand (or combined, see below)
    <package>.go
```

### Thin dispatchers (`cmd_*.go`)

Each `cmd_*.go` file lives in `package main` and contains a single function `cmdXxx(args []string) error`. Its only job is to parse flags with `flag.NewFlagSet` and call the corresponding internal package's `Run` function with options. These files should be ~20-40 lines. No business logic belongs here.

### Internal packages (`internal/`)

Each subcommand's logic lives in its own package under `internal/`. Every package follows the **functional options pattern**:

```go
type Config struct { /* fields with sensible zero values */ }
type Option func(*Config)

func WithFoo(v string) Option { return func(c *Config) { c.Foo = v } }

func Run(opts ...Option) error {
    cfg := &Config{/* defaults */}
    for _, o := range opts { o(cfg) }
    // ...
}
```

Key points:
- Defaults are set in `Run` when constructing `Config`, not in the `With*` functions
- Functions that are tested directly must be exported (e.g., `GeneratePassword`, `DeriveKey`, `JSONQuery`)
- Some packages expose two entry points instead of one: `RunEncode`/`RunDecode` (codec), `RunEncrypt`/`RunDecrypt` (crypt)

### Combined packages

Some CLI subcommands share a package to avoid duplication:
- `encode` + `decode` → `internal/codec`
- `encrypt` + `decrypt` → `internal/crypt`

### Package naming

Several packages use non-obvious names to avoid colliding with stdlib package names:
- `timecmd` (not `time`)
- `jsoncmd` (not `json`)
- `netcmd` (not `net`)
- `imgconv` (not `image`)

Similarly, some internal imports use aliases to avoid collisions:
- `crand "crypto/rand"` (when the package also uses `math/rand/v2`)
- `gohash "hash"` (in the `hash` package)
- `mrand "math/rand/v2"`

### Shared utilities (`internal/shared`)

`FormatSize`, `ReadInput`, and `CryptoRandIntn` are used by multiple packages and live in `internal/shared`. Keep this package small — only add something here if it's genuinely needed by 2+ packages.

### Embedded assets

The directory listing HTML template lives at `internal/serve/templates/directory.html` and is embedded via `//go:embed` in `internal/serve/serve.go`. There is no root-level `templates/` directory.

## Testing

Tests live in `cmd_*_test.go` files in `package main` (not inside the internal packages). This lets tests exercise the full path from `cmdXxx` dispatcher through the internal package.

Common patterns:
- **Round-trip tests**: encode then decode, compress then decompress, encrypt then decrypt
- **Known-value tests**: hash digests, epoch conversions verified against expected output
- **Error path tests**: wrong password, invalid input, unsupported formats
- **Network tests**: spin up local TCP listeners, no external dependencies

Shared helpers in `testhelpers_test.go`:
- `captureStdout(t, func())` — captures os.Stdout output from functions that write directly to it
- `writeTestFile(t, path, content)` — creates a temp file for test input
- `assertContains(t, output, label, value)` — checks that output contains a line with both strings

## Adding a new subcommand

1. Create `internal/<name>/<name>.go` with `Config`, `Option`, `With*` functions, and `Run`
2. Create `cmd_<name>.go` with `cmdXxx(args []string) error` that parses flags and calls `Run`
3. Register it in `main.go`'s command map
4. Create `cmd_<name>_test.go` with tests
5. Update `printUsage()` in `main.go`

## Build and verify

```bash
go build ./...
go test ./...
go vet ./...
```

No `go mod tidy` changes should be needed since there are no external dependencies.
