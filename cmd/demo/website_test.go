// The Fetch website server: the targets it answers and the headers it sets.

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// Catch accidental SPA fallback over an API or acceptance of a decoded target.
func TestFetchWebsiteTargets(t *testing.T) {
	pages := []string{
		"/", "/food", "/mart", "/store/MER-001", "/item/ITM-001", "/cart", "/checkout",
		"/my-orders", "/my-orders/ORD-1001", "/help", "/help/TKT-1001", "/signin",
		"/merchant", "/rider", "/support", "/ops", "/lab", "/account",
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, target := range pages {
			t.Run(method+target, func(t *testing.T) {
				r := httptest.NewRequest(method, target+"?from=link", nil)
				name, contentType, ok := websiteFile(r)
				if !ok || name != "index.html" || contentType != "text/html; charset=utf-8" {
					t.Fatalf("page target returned %q %q %t", name, contentType, ok)
				}
			})
		}
		for file, contentType := range map[string]string{
			"app-1.js": "text/javascript", "app.css": "text/css", "logo.svg": "image/svg+xml", "MER-001.webp": "image/webp",
		} {
			name, gotType, ok := websiteFile(httptest.NewRequest(method, "/assets/"+file, nil))
			if !ok || name != "assets/"+file || gotType != contentType {
				t.Errorf("asset %s: %q %q %t", file, name, gotType, ok)
			}
		}
	}
	for _, target := range []string{
		"/orders", "/orders/ORD-1001", "/orders/mine", "/orders/quote", "/support/tickets", "/internal/stock",
		"/inventory/search", "/accounts/login", "/admin/status", "/demo/", "/demo/assets/app.js",
		"/food/", "/store", "/store/", "/store/a/b", "/my-orders/", "/help/a/b", "/signin/extra",
		"/assets/", "/assets/app.js.map", "/assets/x.png", "/assets/x.jpg", "/assets/x.JS", "/assets/../app.js",
		"/assets/sub/app.js", "/assets/%61pp.js", "/assets/%2e%2e%2fapp.js", "/%66ood", "/store/%2f",
		"/store/.", "/item/..", "//food", "/food//", "/assets/..\\app.js",
	} {
		if _, _, ok := websiteFile(httptest.NewRequest(http.MethodGet, target, nil)); ok {
			t.Errorf("unapproved target served as website: %s", target)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		for _, target := range []string{"/", "/food", "/assets/app.js"} {
			if _, _, ok := websiteFile(httptest.NewRequest(method, target, nil)); ok {
				t.Errorf("unapproved method served as website: %s %s", method, target)
			}
		}
	}
}

// A page and an asset carry the content policy and nosniff; the page is
// never stored, an asset is revalidated by its ETag; a missing asset and any
// other target are 404.
func TestFetchWebsiteResponseHeaders(t *testing.T) {
	files := fstest.MapFS{
		"index.html":          {Data: []byte("test page")},
		"assets/MER-001.webp": {Data: []byte("test image")},
	}
	handler, err := loadWebsite(files)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/", "/food", "/assets/MER-001.webp", "/assets/missing.js", "/orders/mine"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if strings.Contains(target, "missing") || strings.HasPrefix(target, "/orders") {
			if w.Code != http.StatusNotFound {
				t.Errorf("%s: %d, want 404", target, w.Code)
			}
			continue
		}
		if w.Code != http.StatusOK || w.Header().Get("Content-Security-Policy") != sitePolicy || w.Header().Get("X-Content-Type-Options") != "nosniff" ||
			w.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: status %d headers %v", target, w.Code, w.Header())
		}
		page := !strings.HasPrefix(target, "/assets/")
		if page && (w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("ETag") != "") ||
			!page && (w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("ETag") == "") {
			t.Errorf("%s: caching headers %v", target, w.Header())
		}
	}
}

// The shop is read once at start: a file changed or removed afterwards does
// not change the answer; an unchanged file revalidates with 304, and HEAD
// gets the length without the body.
func TestFetchWebsiteServesLoadedBuild(t *testing.T) {
	files := fstest.MapFS{"index.html": {Data: []byte("test page")}, "assets/app.js": {Data: []byte("let a = 1")}}
	handler, err := loadWebsite(files)
	if err != nil {
		t.Fatal(err)
	}
	delete(files, "assets/app.js")
	files["index.html"] = &fstest.MapFile{Data: []byte("changed")}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if w.Code != http.StatusOK || w.Body.String() != "let a = 1" || w.Header().Get("Content-Length") != "9" {
		t.Fatalf("loaded asset: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	again := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	again.Header.Set("If-None-Match", w.Header().Get("ETag"))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, again)
	if w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Fatalf("revalidation: %d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/", nil))
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "9" {
		t.Fatalf("HEAD: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	if _, err := loadWebsite(fstest.MapFS{}); err == nil {
		t.Fatal("a build without index.html was loaded")
	}
}
