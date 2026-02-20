package serve

import (
	"cmp"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"log/slog"
	"math/big"
	"mime"
	"github.com/jftuga/mtool/v2/internal/shared"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

//go:embed templates
var templateFS embed.FS

// DirEntry represents a directory listing entry.
type DirEntry struct {
	Name    string
	Link    string
	Size    string
	ModTime string
	IsDir   bool
}

// Config holds configuration for the serve command.
type Config struct {
	Addr      string
	Dir       string
	EnableGzip bool
	EnableTLS  bool
}

// Option configures a Config.
type Option func(*Config)

func WithAddr(addr string) Option      { return func(c *Config) { c.Addr = addr } }
func WithDir(dir string) Option        { return func(c *Config) { c.Dir = dir } }
func WithGzip(enable bool) Option      { return func(c *Config) { c.EnableGzip = enable } }
func WithTLS(enable bool) Option       { return func(c *Config) { c.EnableTLS = enable } }

// Run starts the HTTP/HTTPS file server.
func Run(opts ...Option) error {
	cfg := &Config{Addr: ":8080", Dir: "."}
	for _, o := range opts {
		o(cfg)
	}

	absDir, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return fmt.Errorf("resolving directory: %w", err)
	}

	dirTmpl, err := LoadDirectoryTemplate()
	if err != nil {
		return fmt.Errorf("loading template: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		reqPath := path.Clean(r.URL.Path)
		filePath := filepath.Join(absDir, filepath.FromSlash(reqPath))

		realPath, err := filepath.EvalSymlinks(filePath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		realRoot, err := filepath.EvalSymlinks(absDir)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !strings.HasPrefix(realPath+string(os.PathSeparator), realRoot+string(os.PathSeparator)) {
			http.NotFound(w, r)
			return
		}

		stat, err := os.Stat(realPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		if stat.IsDir() {
			serveDirectory(w, r, filePath, reqPath, dirTmpl)
			return
		}

		ct := mime.TypeByExtension(filepath.Ext(filePath))
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}

		http.ServeFile(w, r, filePath)
	})

	var handler http.Handler = mux
	if cfg.EnableGzip {
		handler = gzipMiddleware(mux)
	}
	handler = loggingMiddleware(handler)

	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	if cfg.EnableTLS {
		tlsCert, err := GenerateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("generating TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		scheme := "http"
		if cfg.EnableTLS {
			scheme = "https"
		}
		slog.Info("serving files", "addr", cfg.Addr, "dir", absDir, "scheme", scheme)

		var listenErr error
		if cfg.EnableTLS {
			listenErr = srv.ListenAndServeTLS("", "")
		} else {
			listenErr = srv.ListenAndServe()
		}
		if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			log.Fatal(listenErr)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down server")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

// GenerateSelfSignedCert creates an in-memory ECDSA P-256 self-signed TLS certificate.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}

	serialNumber, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"mtool self-signed"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	certDER, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshaling key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func serveDirectory(w http.ResponseWriter, _ *http.Request, dirPath, urlPath string, tmpl *template.Template) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "failed to read directory", http.StatusInternalServerError)
		return
	}

	var items []DirEntry
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		size := shared.FormatSize(info.Size())
		if e.IsDir() {
			size = "-"
		}
		items = append(items, DirEntry{
			Name:    e.Name(),
			Link:    url.PathEscape(e.Name()),
			Size:    size,
			ModTime: info.ModTime().Format(time.DateTime),
			IsDir:   e.IsDir(),
		})
	}

	slices.SortFunc(items, func(a, b DirEntry) int {
		if a.IsDir != b.IsDir {
			if a.IsDir {
				return -1
			}
			return 1
		}
		return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})

	data := struct {
		Path    string
		Entries []DirEntry
	}{
		Path:    urlPath,
		Entries: items,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		slog.Error("template execution failed", "error", err)
	}
}

// LoadDirectoryTemplate loads the HTML template for directory listings.
func LoadDirectoryTemplate() (*template.Template, error) {
	tmplBytes, err := fs.ReadFile(templateFS, "templates/directory.html")
	if err == nil {
		return template.New("directory").Parse(string(tmplBytes))
	}
	return template.New("directory").Parse(defaultDirectoryTemplate)
}

const defaultDirectoryTemplate = `<!DOCTYPE html>
<html><head><title>Index of {{.Path}}</title>
<style>body{font-family:monospace;margin:2em}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:4px 12px}tr:hover{background:#f0f0f0}</style>
</head><body><h1>Index of {{.Path}}</h1><table><tr><th>Name</th><th>Size</th><th>Modified</th></tr>
{{range .Entries}}<tr><td>{{if .IsDir}}📁{{else}}📄{{end}} <a href="{{.Link}}{{if .IsDir}}/{{end}}">{{.Name}}</a></td>
<td>{{.Size}}</td><td>{{.ModTime}}</td></tr>{{end}}</table></body></html>`

type gzipResponseWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	return g.writer.Write(b)
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		gz, err := gzip.NewWriterLevel(w, flate.DefaultCompression)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		defer gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, writer: gz}, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration", time.Since(start).String(),
		)
	})
}
