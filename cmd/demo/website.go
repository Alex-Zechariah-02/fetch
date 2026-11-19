// The Fetch website server: the built shop on its own loopback upstream,
// reached only through the gateway's public website operations. It answers
// only the shop's client routes and its flat assets directory; everything
// else is 404.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
)

// sitePolicy lets the shop load only its own scripts, styles and images and
// call only its own origin, and forbids framing, so injected markup cannot
// run script or send data elsewhere.
const sitePolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// assetTypes are the only asset types served, each with a fixed content type
// rather than one guessed from the host's registry.
var assetTypes = map[string]string{
	".js":   "text/javascript",
	".css":  "text/css",
	".svg":  "image/svg+xml",
	".webp": "image/webp",
}

// sitePages are the shop's exact client routes, and sitePrefixes those that
// take one more path segment (an ID or a name); every one returns the page.
var (
	sitePages = []string{"/", "/food", "/mart", "/cart", "/checkout", "/my-orders", "/help", "/signin",
		"/merchant", "/rider", "/support", "/ops", "/lab", "/account"}
	sitePrefixes = []string{"/store/", "/item/", "/my-orders/", "/help/"}
)

// page is one file of the shop, loaded at start.
type page struct {
	data        []byte
	contentType string
	tag         string // strong ETag: the content's SHA-256
}

// loadWebsite reads the built shop in files once, its page and every asset of
// a served type, and serves them from memory: the build does not change while
// a demonstration runs. Browsers revalidate each file by its ETag, so an
// unchanged file costs a 304 and no body.
func loadWebsite(files fs.FS) (http.Handler, error) {
	pages := map[string]page{}
	add := func(name, contentType string) error {
		data, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		pages[name] = page{data, contentType, `"` + hex.EncodeToString(sum[:16]) + `"`}
		return nil
	}
	if err := add("index.html", "text/html; charset=utf-8"); err != nil {
		return nil, fmt.Errorf("the shop's page: %w", err)
	}
	assets, err := fs.ReadDir(files, "assets")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, entry := range assets {
		contentType := assetTypes[path.Ext(entry.Name())]
		if entry.Type().IsRegular() && contentType != "" && isPlainName(entry.Name()) {
			if err := add("assets/"+entry.Name(), contentType); err != nil {
				return nil, err
			}
		}
	}
	return website(pages), nil
}

// website serves pages, the loaded shop.
func website(pages map[string]page) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, _, ok := websiteFile(r)
		file, found := pages[name]
		if !ok || !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", file.contentType)
		w.Header().Set("Content-Security-Policy", sitePolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Kept, but checked again on every use: a rebuilt shop shows at once.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", file.tag)
		// ServeContent answers If-None-Match with 304, sets Content-Length and sends no body to HEAD.
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(file.data))
	})
}

// websiteFile names the page at an approved client route, or a file of the
// flat assets directory at /assets/<name>. The target is compared as
// received, before any decoding, and an asset name may hold only letters,
// digits, '.', '-' and '_', so no target reaches any other file.
func websiteFile(r *http.Request) (name, contentType string, ok bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "", "", false
	}
	target, _, _ := strings.Cut(r.RequestURI, "?")
	if isWebsitePage(target) {
		return "index.html", "text/html; charset=utf-8", true
	}
	asset, found := strings.CutPrefix(target, "/assets/")
	contentType = assetTypes[path.Ext(asset)]
	if !found || contentType == "" || !isPlainName(asset) {
		return "", "", false
	}
	return "assets/" + asset, contentType, true
}

// isWebsitePage reports whether target is an exact client route, or a
// prefixed route with one segment of visible ASCII other than '\' and '%'
// that is not a dot segment.
func isWebsitePage(target string) bool {
	if slices.Contains(sitePages, target) {
		return true
	}
	for _, prefix := range sitePrefixes {
		if id, found := strings.CutPrefix(target, prefix); found && isSegment(id) {
			return true
		}
	}
	return false
}

func isSegment(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; c < 0x21 || c > 0x7e || c == '/' || c == '\\' || c == '%' {
			return false
		}
	}
	return true
}

// isPlainName accepts a nonempty name of letters, digits, '.', '-' and '_'.
func isPlainName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// shopWrite lets the largest shop asset reach a slow link; it also covers
// forwarded answers, which take at most the services' own 10 s.
const shopWrite = 30 * time.Second

// demoServer bounds every connection of a demo server as the services do;
// write must outlast the slowest answer handler gives. Idle connections stay
// two minutes, past the gateway's own idle close, as in services.Run.
func demoServer(handler http.Handler, write time.Duration) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: write, IdleTimeout: 2 * time.Minute}
}

// serveWebsite serves site on listener until ctx ends, then stops within
// the bound and reports why the server ended, nil for a requested stop. The
// write deadline lets the largest shop asset reach a slow link.
func serveWebsite(ctx context.Context, listener net.Listener, site http.Handler) error {
	server := demoServer(site, shopWrite)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		// Five seconds let in-flight answers finish, then the website stop gives up.
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		<-stopped
		return nil
	}
	return err
}
