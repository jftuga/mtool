# TODO — mtool 1.2.0

These items were identified during a security/code review of mtool v1.1.0.
They are improvements and usability fixes, not security issues (the security
issues were resolved in 1.1.0).

mtool is a single-binary Swiss army knife CLI written in Go using exclusively
stdlib packages. The project's identity is "as many stdlib packages as feasible"
(currently 94). Any changes should avoid reducing that count.

Source: single-file project — all code is in `main.go`, tests in `main_test.go`.

---

## 1. Archive creation stores absolute/host paths

**Problem:** When creating tar.gz or zip archives, `header.Name` is set to the
full path `p` as walked by `filepath.Walk` (see ~lines 1079, 1125, 1171 in
`main.go`). This means archives contain entries like `/home/user/proj/file.txt`
or `C:\Users\user\proj\file.txt` instead of relative paths like `proj/file.txt`.

When extracted elsewhere (especially with the path traversal guards added in
v1.1.0), this can cause unexpected directory structures or extraction failures.

**Fix:** Make archive entry names relative to the walked root. For each walk root:
- Compute `base := filepath.Clean(root)`
- For each path `p`, compute `rel, _ := filepath.Rel(base, p)` (or
  `filepath.Rel(filepath.Dir(base), p)` to include the root dir name)
- Set `header.Name = filepath.ToSlash(rel)` to ensure forward slashes (portable)

**Search for:** `header.Name = p` in `main.go` — there are 3 occurrences
(tar.gz, zip, and tar.zlib creation paths).

**Stdlib impact:** None — `filepath` and `path` are already imported.

---

## 2. Directory listing hrefs not URL-escaped

**Problem:** In `serveDirectory`, the HTML template at ~line 415 renders
directory entry links as:

```html
<a href="{{.Name}}{{if .IsDir}}/{{end}}">{{.Name}}</a>
```

Go's `html/template` auto-escapes for HTML safety, but it does NOT produce
valid URL paths. Filenames containing spaces, `#`, `?`, `&`, etc. will generate
broken links (e.g., `<a href="my file.txt">` instead of `<a href="my%20file.txt">`).

**Fix:** Add a URL-escaped field to the template data. In the `serveDirectory`
function (~line 351), the entries are built with just `.Name` and `.IsDir`.
Add a `.Href` field that uses `url.PathEscape(e.Name())`. Then update the
template to use `{{.Href}}` in the `href` attribute and keep `{{.Name}}` for
display text.

`net/url` is already imported, so no new imports needed.

**Stdlib impact:** None.

---

## 3. `topLatencies` heap in bench is dead code

**Problem:** In `cmdBench` (~line 1492), a `latencyHeap` is created and values
are pushed to it, but the heap is never read/popped. This means `container/heap`
is imported and used but the feature is incomplete — there's no "top-N slowest
requests" output.

**Two options:**
1. **Complete the feature:** After the benchmark run, pop the top-N values from
   the heap and print them as "Slowest requests" in the results summary. This
   preserves the `container/heap` import with a useful purpose.
2. **Remove it:** Delete `topLatencies` and the `heap.Push` call. But WARNING:
   this would remove the only usage of `container/heap`, dropping the stdlib
   package count from 94 to 93. Option 1 is preferred.

**Search for:** `topLatencies` in `main.go` — 3 occurrences (init, heap.Init,
heap.Push). Also see `latencyHeap` type definition (search for `type latencyHeap`).

---

## 4. `strings.ToTitle` does not produce title case

**Problem:** The `transform -mode title` subcommand uses `strings.ToTitle()`,
which uppercases ALL letters in the string (e.g., "hello world" becomes
"HELLO WORLD"), not title case ("Hello World"). This is a known gotcha in Go's
stdlib — `strings.ToTitle` maps every letter to its title-case Unicode form,
which for Latin text is just uppercase.

**Fix:** Implement simple word-based title casing: split on word boundaries,
uppercase the first letter of each word, lowercase the rest. This can be done
with stdlib only using `strings.Fields`, `unicode.ToUpper`, `unicode.ToLower`,
and `strings.Builder`.

Alternatively, rename the mode from `title` to something that accurately
describes what `strings.ToTitle` does, and add a separate true title-case mode.

**Search for:** `mode.*title` or `ToTitle` in `main.go`.

**Stdlib impact:** None — all needed packages are already imported.

---

## Nice-to-have: Repeatable `-header` flag in fetch

**Problem:** `cmdFetch` only accepts a single `-header` flag. Users often need
to set multiple headers (e.g., Authorization + Content-Type).

**Fix:** Use a custom `flag.Value` implementation that appends to a slice on
each `-header` invocation. This is idiomatic Go for repeatable flags. Search
for `cmdFetch` and the `-header` flag definition in `main.go`.

**Stdlib impact:** None.

---

## Nice-to-have: `filepath.Rel` containment checks

**Problem:** The path traversal guards added in v1.1.0 use
`strings.HasPrefix(filepath.Clean(target)+sep, filepath.Clean(base)+sep)`.
This works correctly on Unix but could theoretically have edge cases on Windows
(drive letters, UNC paths). A more idiomatic approach uses `filepath.Rel`.

**Fix:** Create a reusable helper:

```go
func isWithinBase(base, target string) bool {
    rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(target))
    if err != nil {
        return false
    }
    return !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}
```

Replace the three `strings.HasPrefix` containment checks (in `extractTarStream`,
`extractZip`, and the `serve` handler) with calls to this helper.

**Search for:** `strings.HasPrefix(filepath.Clean` in `main.go` — 3 occurrences.

**Stdlib impact:** None.

---

## Note: PBKDF2 signature is CORRECT

An external reviewer claimed `pbkdf2.Key(sha256.New, string(password), salt, iter, keyLen)`
is wrong, referencing the old `golang.org/x/crypto/pbkdf2` API. This is incorrect.
The Go 1.24+ **stdlib** `crypto/pbkdf2.Key` has the signature:

```go
func Key[Hash hash.Hash](h func() Hash, password string, salt []byte, iter, keyLength int) ([]byte, error)
```

Hash function is the FIRST parameter, password is a `string`. The current code
is correct. Do NOT change this. Verified via `go doc crypto/pbkdf2.Key`.
