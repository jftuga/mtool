# mtool (multi-tool)

![Code Base: AI Vibes](https://img.shields.io/badge/Code%20Base-AI%20Vibes%20%F0%9F%A4%A0-blue)

`mtool` is a Swiss army knife CLI utility written in Go, using exclusively standard library packages.

## Motivation

The goal of this project was to write a practical CLI tool in Go that incorporates as many standard library modules as feasible without any third-party dependencies. Rather than contriving artificial usage, each package is pulled in naturally through a set of subcommands that solve real, everyday tasks: serving files, fetching URLs, hashing data, inspecting TLS certificates, benchmarking endpoints, converting images and more.

The result is a single-binary multi-tool that leverages **93 unique standard library packages**.

## Disclaimer

This software was developed with the assistance of AI (Anthropic Claude). It is
provided "as is", without warranty of any kind, express or implied. **Use at your
own risk.** The author assumes no liability for any damages arising from its use.

## Use Cases

- **Minimal / distroless Docker containers** - A single static binary replaces `curl`, `openssl`, `sha256sum`, `base64`, `tar`, `gzip`, and more. A `FROM scratch` image with just `mtool` can be under 15 MB.
- **CI/CD pipelines** - Hash verification, archive creation, secret generation, and endpoint benchmarking without installing multiple tools or adding dependencies.
- **Air-gapped / restricted environments** - No package manager or network access needed. Copy one binary and get a full toolkit.
- **Incident response** - Drop a single binary onto a system to hash files, inspect TLS certificates, check DNS records, or fetch URLs.
- **Embedded / IoT systems** - Constrained environments where installing a full toolchain is impractical.
- **Cross-platform developer tooling** - Consistent behavior across macOS, Linux, and Windows without platform-specific alternatives.

## Installation

**Homebrew**
```bash
brew tap jftuga/homebrew-tap
brew update
brew install jftuga/tap/mtool
```

**Source**
```bash
git clone https://github.com/jftuga/mtool.git
cd mtool
go build -ldflags="-s -w" -o mtool
```

Requires Go 1.26 or later. No third-party dependencies.

## Usage

```
mtool <command> [options]
```

Run `mtool <command> -h` for help on any subcommand.

## Subcommands

| Command | Description | Key stdlib packages |
|---|---|---|
| `serve` | Start an HTTP/HTTPS file server with directory listing, optional gzip, and self-signed TLS | `net/http`, `html/template`, `compress/gzip`, `compress/flate`, `embed`, `io/fs`, `mime`, `os/signal`, `context`, `syscall`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/x509/pkix` |
| `fetch` | Fetch a URL and display response details, with cookie support and timing trace | `net/http`, `net/http/httputil`, `net/http/httptrace`, `net/http/cookiejar`, `net/url` |
| `hash` | Compute hashes of files or stdin | `crypto/md5`, `crypto/sha1`, `crypto/sha256`, `crypto/sha512`, `crypto/sha3`, `crypto/hmac`, `hash`, `hash/adler32`, `hash/crc32`, `hash/crc64`, `hash/fnv`, `encoding/hex` |
| `encode` | Encode data (base64, base32, hex, ascii85, URL, HTML entities, quoted-printable, UTF-16) | `encoding/base64`, `encoding/base32`, `encoding/ascii85`, `encoding/hex`, `html`, `net/url`, `mime/quotedprintable`, `unicode/utf16` |
| `decode` | Decode data (base64, base32, hex, ascii85, URL, HTML entities, quoted-printable, UTF-16) | `encoding/base64`, `encoding/base32`, `encoding/ascii85`, `encoding/hex`, `html`, `net/url`, `mime/quotedprintable`, `unicode/utf16` |
| `info` | Display system and network information in multiple formats | `runtime`, `runtime/debug`, `encoding/json`, `encoding/xml`, `encoding/csv`, `reflect`, `text/tabwriter`, `net`, `net/netip`, `os/user`, `maps` |
| `archive` | Create tar.gz or zip archives | `archive/tar`, `archive/zip`, `compress/gzip`, `path/filepath` |
| `generate` | Generate passwords, tokens, UUIDs, or random data | `crypto/rand`, `math/big`, `encoding/binary` |
| `bench` | Benchmark an HTTP endpoint with concurrency, jitter, and percentile stats | `sync`, `sync/atomic`, `container/list`, `math`, `math/rand/v2`, `sort` |
| `inspect` | Inspect TLS certificates or DNS records | `crypto/tls`, `crypto/x509`, `encoding/pem`, `net`, `net/netip` |
| `transform` | Transform text (case, sort, grep, frequency, replace, and more) | `regexp`, `unicode`, `unicode/utf8`, `bufio`, `slices`, `cmp`, `strconv` |
| `image` | Convert images between PNG, JPEG, and GIF formats with dithering | `image`, `image/png`, `image/jpeg`, `image/gif`, `image/draw`, `image/color/palette` |
| `encrypt` | Encrypt a file with AES-256-GCM using a password-derived key | `crypto/aes`, `crypto/cipher`, `crypto/pbkdf2`, `crypto/sha256`, `crypto/rand` |
| `decrypt` | Decrypt a file encrypted with the encrypt command | `crypto/aes`, `crypto/cipher`, `crypto/pbkdf2` |
| `compress` | Compress or decompress data (gzip, zlib, lzw, bzip2) | `compress/bzip2`, `compress/gzip`, `compress/lzw`, `compress/zlib` |
| `time` | Convert timestamps (now, toepoch, fromepoch, convert timezones) | `time`, `strconv` |
| `json` | Process JSON (pretty-print, compact, validate, dot-path query) | `encoding/json`, `strconv` |
| `net` | Network utilities (TCP check, port scan, wait, echo server) | `net`, `sync`, `strconv` |
| `jwt` | Decode JWT tokens without verification (header, payload, expiry) | `encoding/base64`, `encoding/json`, `time` |

## Examples

### Serve files over HTTP

```bash
mtool serve -addr :9000 -dir ./public -gzip
```

### Serve files over HTTPS with self-signed certificate

```bash
mtool serve -addr :4443 -dir . -tls
# Access with: curl -k https://localhost:4443
```

### Fetch a URL

```bash
mtool fetch -headers https://example.com
mtool fetch -trace https://example.com
mtool fetch -method POST -body '{"key":"val"}' -output response.json https://api.example.com
```

### Hash files

```bash
mtool hash -algo sha256 myfile.txt
echo "hello" | mtool hash -algo md5
mtool hash -algo sha3-256 myfile.txt
mtool hash -algo sha256 -hmac "secret-key" myfile.txt
mtool hash -algo crc64 myfile.txt
mtool hash -algo adler32 myfile.txt
mtool hash -algo fnv64 myfile.txt
```

### Encode and decode

```bash
echo "hello world" | mtool encode -format base64
echo "aGVsbG8gd29ybGQK" | mtool decode -format base64
echo "hello" | mtool encode -format base32
echo "hello" | mtool encode -format ascii85
echo "foo bar" | mtool encode -format url
echo '<div class="test">foo & bar</div>' | mtool encode -format html
echo '&lt;div&gt;foo &amp; bar&lt;/div&gt;' | mtool decode -format html
echo "Héllo wörld" | mtool encode -format qp
echo "H=C3=A9llo" | mtool decode -format qp
echo "hello" | mtool encode -format utf16 > output.utf16
mtool decode -format utf16 output.utf16
```

### System information

```bash
mtool info
mtool info -format json
mtool info -format xml -env
mtool info -format csv
```

### Create archives

```bash
mtool archive -format zip -output backup.zip src/ docs/ README.md
mtool archive -format tar.gz myproject/
mtool archive -format tar.zlib myproject/
mtool archive -extract backup.zip
mtool archive -extract -output ./dest archive.tar.gz
mtool archive -extract archive.tar.bz2
```

### Generate secrets

```bash
mtool generate -mode password -length 32
mtool generate -mode password -length 16 -charset alnum
mtool generate -mode token -length 64
mtool generate -mode uuid -count 5
mtool generate -mode bigint -length 256
```

### Benchmark an HTTP endpoint

```bash
mtool bench -n 500 -c 20 https://example.com
mtool bench -n 1000 -c 50 -method POST https://api.example.com/health
mtool bench -n 500 -c 20 -jitter 100ms https://example.com
```

### Inspect TLS certificates

```bash
mtool inspect -mode tls google.com
mtool inspect -mode tls -port 8443 internal.example.com
```

### Inspect DNS records

```bash
mtool inspect -mode dns github.com
```

### Transform text

```bash
# Case conversion
echo "hello world" | mtool transform -mode upper
echo "HELLO WORLD" | mtool transform -mode lower

# Sort lines
cat names.txt | mtool transform -mode sort
cat scores.txt | mtool transform -mode sort -numeric -reverse
cat data.txt | mtool transform -mode sort -field 3 -numeric
cat mixed.txt | mtool transform -mode sort -ignore-case

# Search and replace with regex
cat log.txt | mtool transform -mode grep -pattern "ERROR|WARN"
cat messy.txt | mtool transform -mode replace -pattern "\s+" -replacement " "

# Text statistics and word frequency
cat document.txt | mtool transform -mode count
cat document.txt | mtool transform -mode freq

# Deduplicate and reverse
cat dupes.txt | mtool transform -mode uniq
echo "hello" | mtool transform -mode reverse
```

### Convert images

```bash
mtool image photo.png photo.jpg
mtool image -quality 75 screenshot.png compressed.jpg
mtool image photo.jpg photo.gif
mtool image -format png input.gif output.png
```

### Encrypt and decrypt files

```bash
mtool encrypt -password "my-secret" document.pdf document.pdf.enc
mtool decrypt -password "my-secret" document.pdf.enc document.pdf

# Or use an environment variable for the password
export MTOOL_PASSWORD="my-secret"
mtool encrypt document.pdf document.pdf.enc
mtool decrypt document.pdf.enc document.pdf
```

### Compress and decompress

```bash
mtool compress -format gzip largefile.txt largefile.txt.gz
mtool compress -d -format gzip largefile.txt.gz largefile.txt
mtool compress -format zlib data.bin data.bin.zlib
mtool compress -d -format zlib data.bin.zlib data.bin
mtool compress -format lzw data.bin data.bin.lzw
mtool compress -d -format lzw data.bin.lzw data.bin
mtool compress -d -format bzip2 data.bz2 data.txt
mtool compress -level 9 -format gzip archive.tar archive.tar.gz
```

> **Note:** bzip2 supports decompression only (Go's `compress/bzip2` package provides a reader but no writer).

### Timestamps

```bash
mtool time -mode now
mtool time -mode toepoch "2024-01-15T10:30:00Z"
mtool time -mode fromepoch 1700000000
mtool time -mode convert -zone America/New_York "2024-01-15T10:30:00Z"
mtool time -mode fromepoch -format "2006-01-02" 1700000000
```

### JSON processing

```bash
echo '{"name":"alice","age":30}' | mtool json -mode pretty
echo '{"name":"alice","age":30}' | mtool json -mode compact
echo '{"name":"alice"}' | mtool json -mode validate
echo '{"user":{"name":"alice"}}' | mtool json -mode query -query .user.name
echo '{"items":[{"id":1},{"id":2}]}' | mtool json -mode query -query ".items[0].id"
```

### Network utilities

```bash
mtool net -mode check localhost:8080
mtool net -mode scan -start 80 -end 443 example.com
mtool net -mode wait -timeout 30s localhost:5432
mtool net -mode echo -addr :9999
```

### JWT decoding

```bash
mtool jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
mtool jwt -raw <token>
```

## Standard Library Packages

The following 93 packages from the Go standard library are used:

`archive/tar`, `archive/zip`, `bufio`, `bytes`, `cmp`, `compress/bzip2`, `compress/flate`, `compress/gzip`, `compress/lzw`, `compress/zlib`, `container/list`, `context`, `crypto/aes`, `crypto/cipher`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/hmac`, `crypto/md5`, `crypto/pbkdf2`, `crypto/rand`, `crypto/sha1`, `crypto/sha256`, `crypto/sha3`, `crypto/sha512`, `crypto/tls`, `crypto/x509`, `crypto/x509/pkix`, `embed`, `encoding/ascii85`, `encoding/base32`, `encoding/base64`, `encoding/binary`, `encoding/csv`, `encoding/hex`, `encoding/json`, `encoding/pem`, `encoding/xml`, `errors`, `flag`, `fmt`, `hash`, `hash/adler32`, `hash/crc32`, `hash/crc64`, `hash/fnv`, `html`, `html/template`, `image`, `image/color/palette`, `image/draw`, `image/gif`, `image/jpeg`, `image/png`, `io`, `io/fs`, `log`, `log/slog`, `maps`, `math`, `math/big`, `math/rand/v2`, `mime`, `mime/quotedprintable`, `net`, `net/http`, `net/http/cookiejar`, `net/http/httptrace`, `net/http/httputil`, `net/netip`, `net/url`, `os`, `os/exec`, `os/signal`, `os/user`, `path`, `path/filepath`, `reflect`, `regexp`, `runtime`, `runtime/debug`, `slices`, `sort`, `strconv`, `strings`, `sync`, `sync/atomic`, `syscall`, `text/tabwriter`, `text/template/parse`, `time`, `unicode`, `unicode/utf16`, `unicode/utf8`

## Tests

Run with `go test -v ./...`

| Test | What it verifies |
|---|---|
| `TestFormatSize` | Byte formatting across B, KB, MB, GB, TB boundaries |
| `TestTLSVersionString` | TLS version code to string mapping, including unknown versions |
| `TestPercentile` | Empty slice, single-element, and various percentile calculations |
| `TestGeneratePassword` | Correct length, charset constraints (alpha/alnum/full), category coverage for full charset |
| `TestGenerateToken` | Correct length, hex-only characters, uniqueness across calls |
| `TestGenerateUUID` | V4 format (version nibble = `4`, variant = `[89ab]`), uniqueness across calls |
| `TestGenerateBigInt` | Returns decimal digit strings for various bit widths |
| `TestSortLines` | Alphabetical, reverse, numeric, numeric descending, case-insensitive, field-based, out-of-range field, non-numeric lines in numeric mode |
| `TestPrintTextStats` | Line/word/letter/digit/byte counts, empty input, no-trailing-newline edge case, unicode |
| `TestPrintWordFrequency` | Frequency ordering (most frequent first), case-insensitive folding |
| `TestCreateTarGz` | Round-trip: create tar.gz, read it back, verify file contents |
| `TestCreateZip` | Round-trip: create zip, read it back, verify file contents |
| `TestCreateTarGzDirectory` | Recursive directory archiving preserves structure and nested files |
| `TestLoadDirectoryTemplate` | Embedded template parses and renders with sample data |
| `TestGenerateSelfSignedCert` | Certificate is self-signed, has correct subject/DNS/IP, valid for ~24h, usable by `tls.Config`, unique serial numbers |
| `TestInferImageFormat` | Extension-to-format mapping for png/jpg/jpeg/gif, case insensitivity, unknown extensions |
| `TestEncodeImage_PNG` | PNG encode/decode round-trip preserves dimensions |
| `TestEncodeImage_JPEG` | JPEG encode/decode round-trip preserves dimensions |
| `TestEncodeImage_GIF` | GIF encode/decode round-trip preserves dimensions |
| `TestEncodeImage_Unsupported` | Unsupported format returns an error |
| `TestImageRoundTrip` | Full PNG->JPEG->GIF->PNG conversion chain via `cmdImage`, verifying file output at each step |
| `TestDeriveKey` | Deterministic output, correct key length (32 bytes), different passwords/salts produce different keys |
| `TestEncryptDecryptRoundTrip` | Encrypt then decrypt, verify content matches original, encrypted data differs from plaintext |
| `TestDecryptWrongPassword` | Decryption fails with incorrect password |
| `TestEncryptProducesUniqueOutput` | Same file encrypted twice produces different ciphertext (unique salt/nonce) |
| `TestCompressDecompressGzip` | Gzip round-trip: compress then decompress, verify content matches and compressed size is smaller |
| `TestCompressDecompressZlib` | Zlib round-trip: compress then decompress, verify content matches and compressed size is smaller |
| `TestCompressDecompressBzip2` | Bzip2 decompression: compress with system bzip2, decompress with mtool, verify content matches |
| `TestCompressBzip2RejectsCompress` | Attempting bzip2 compression returns a clear "decompress only" error |
| `TestCompressDecompressLZW` | LZW round-trip with litwidths 6, 7, 8: compress with header, decompress auto-detects litwidth |
| `TestHashAdler32` | Adler-32 hash produces correct output for known input |
| `TestHashCRC64` | CRC-64 hash produces correct output for known input |
| `TestHashFNV` | FNV-32a, FNV-64a, FNV-128a produce correct output lengths for known input |
| `TestEncodeDecodeQuotedPrintable` | Quoted-printable round-trip: encode then decode, verify non-ASCII is encoded and round-trips correctly |
| `TestEncodeDecodeUTF16` | UTF-16 round-trip: encode with BOM then decode, verify content matches including non-ASCII characters |
| `TestEncodeDecodeBase64` | Base64 round-trip: encode then decode, verify content matches |
| `TestEncodeDecodeBase32` | Base32 round-trip: encode then decode, verify content matches |
| `TestEncodeDecodeHex` | Hex round-trip: encode verifies known value, decode restores original |
| `TestEncodeDecodeAscii85` | Ascii85 round-trip: encode then decode, verify content matches |
| `TestEncodeDecodeURL` | URL encoding round-trip: verifies special characters are percent-encoded and decode restores original |
| `TestEncodeDecodeHTML` | HTML entity round-trip: verifies `<`, `>`, `&`, `"` are escaped and decode restores original |
| `TestTransformUpper` | Lowercase text converted to uppercase |
| `TestTransformLower` | Uppercase text converted to lowercase |
| `TestTransformReverse` | String reversal produces correct output |
| `TestTransformGrep` | Regex filtering selects only matching lines |
| `TestTransformReplace` | Regex replacement collapses whitespace correctly |
| `TestTransformUniq` | Deduplication removes repeated lines, preserves order |
| `TestHashAlgorithms` | All hash algorithms (md5, sha1, sha256, sha512, sha3-256, sha3-512, crc32) produce correct hex output lengths |
| `TestHashHMAC` | HMAC differs from plain hash, is deterministic, and different keys produce different output |
| `TestArchiveExtractTarGz` | Create tar.gz then extract, verify extracted file contents match originals |
| `TestArchiveExtractZip` | Create zip then extract, verify extracted file contents match originals |
| `TestCreateTarZlib` | Tar.zlib round-trip: create then extract, verify file contents match |
| `TestCompressGzipLevels` | Gzip level 9 produces smaller output than level 1 for the same input |
| `TestParseFlexibleTime` | Table-driven: RFC3339, ISO date, US date, named months, epoch seconds, error cases |
| `TestTimeNow` | Output contains Local/UTC/RFC3339/Epoch labels |
| `TestTimeFromEpoch` | Epoch 0 → 1970-01-01; known epoch → correct date |
| `TestTimeToEpoch` | Known date → correct epoch |
| `TestTimeConvert` | Timezone conversion correctness |
| `TestJSONPretty` | Compact input → indented output with newlines |
| `TestJSONCompact` | Indented input → single-line output |
| `TestJSONValidate` | Valid/invalid JSON detection |
| `TestJSONQuery` | Dot-path on nested objects/arrays, error on missing keys and out-of-range indices |
| `TestNetCheck` | Open port succeeds with positive duration, closed port fails |
| `TestNetScan` | Finds known open port in single-port range |
| `TestNetWait` | Succeeds when port is open; times out when it isn't |
| `TestNetEcho` | Echoed data matches sent data |
| `TestDecodeJWT` | Manually-built JWT decodes correctly with expected header/payload fields |
| `TestDecodeJWTInvalid` | Wrong part count returns error |
| `TestFormatJWTExpiry` | Past/future/missing exp and iat/nbf claims handled correctly |
| `TestJWTFromArg` | End-to-end cmdJWT produces Header/Payload output |

## Personal Project Disclosure

This program is my own original idea, conceived and developed entirely:

* On my own personal time, outside of work hours
* For my own personal benefit and use
* On my personally owned equipment
* Without using any employer resources, proprietary information, or trade secrets
* Without any connection to my employer's business, products, or services
* Independent of any duties or responsibilities of my employment

This project does not relate to my employer's actual or demonstrably
anticipated research, development, or business activities. No
confidential or proprietary information from any employer was used
in its creation.
