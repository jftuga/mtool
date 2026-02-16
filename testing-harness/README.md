# Shell Script Testing Harness

Black-box integration tests that exercise the compiled `mtool` binary end-to-end. These complement the Go unit tests (`go test ./...`) by testing real flag parsing, stdin/stdout piping, exit codes, and multi-process interactions.

## Running

```bash
# from the repo root
go build -o mtool .
bash testing-harness/test-all.sh
```

Or point to a custom binary:

```bash
MTOOL=/path/to/mtool bash testing-harness/test-all.sh
```

## Structure

| File | Subcommand | What it tests |
|------|-----------|---------------|
| `test-all.sh` | — | Master runner; discovers and runs all `test-*.sh` scripts |
| `test-archive.sh` | `archive` | `-format` (tar.gz, tar.zlib, zip), `-output`, `-extract`, directory archiving |
| `test-bench.sh` | `bench` | `-n`, `-c`, `-jitter`, `-method` against a local server |
| `test-compress.sh` | `compress` | `-format` (gzip, zlib, lzw), `-d`, `-level`, `-litwidth`, bzip2 compress rejection |
| `test-decode.sh` | `decode` | `-format` round-trips for all formats, known-value decodes, file input |
| `test-decrypt.sh` | `decrypt` | `-password`, wrong password failure, `MTOOL_PASSWORD` env var, corrupted file |
| `test-encode.sh` | `encode` | `-format` for all formats, known-value encodes, file input |
| `test-encrypt.sh` | `encrypt` | `-password`, ciphertext differs from plaintext, round-trip, `MTOOL_PASSWORD` env var |
| `test-fetch.sh` | `fetch` | `-method`, `-header`, `-body`, `-timeout`, `-headers`, `-dump`, `-trace`, `-output` |
| `test-generate.sh` | `generate` | `-mode` (password, token, bytes, uuid, bigint), `-length`, `-count`, `-charset`, uniqueness |
| `test-hash.sh` | `hash` | `-algo` (all 12 algorithms), `-hmac`, stdin pipe, known digest values |
| `test-image.sh` | `image` | `-format`, `-quality`, PNG/JPG/GIF conversions, JPEG magic byte verification |
| `test-info.sh` | `info` | `-format` (table, json, xml, csv), `-env` |
| `test-inspect.sh` | `inspect` | `-mode tls`, `-mode dns`, `-port` (requires network access to example.com) |
| `test-json.sh` | `json` | `-mode` (pretty, compact, validate, query), `-query` with dot-path and array index, `-indent`, invalid JSON |
| `test-jwt.sh` | `jwt` | Known token decode, `-raw`, invalid token failure |
| `test-net.sh` | `net` | `-mode` (check, scan, wait, echo), `-timeout`, `-start`/`-end` port range |
| `test-serve.sh` | `serve` | `-addr`, `-dir`, `-gzip`, `-tls` with curl verification |
| `test-time.sh` | `time` | `-mode` (now, fromepoch, toepoch, convert), `-format`, `-zone` |
| `test-transform.sh` | `transform` | `-mode` (all 10 modes), `-pattern`, `-replacement`, `-numeric`, `-reverse`, `-ignore-case`, `-field` |

## Conventions

- Every script uses `set -euo pipefail` and cleans up temp files via `trap ... EXIT`
- Network tests use local servers (`mtool serve`, `mtool net -mode echo`) to avoid external dependencies, except `test-inspect.sh` which needs a real TLS/DNS target
- Free ports are obtained via `python3 -c 'import socket; ...'`
- Each script prints `<subcommand>: all tests passed` on success

## Adding a new test

Create `test-<name>.sh` following the pattern of existing scripts. The master runner automatically picks up any new `test-*.sh` file in this directory.

## Prerequisites

- `mtool` binary (built with `go build -o mtool .`)
- `python3` (for free port allocation)
- `curl` (for serve/fetch/bench tests)
- `xxd` (for image magic byte checks)
- `base64` (for creating test images)
