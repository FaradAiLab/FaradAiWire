package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
	"sync"
)

//go:embed all:dist
var distFS embed.FS

var (
	spaHandlerOnce sync.Once
	cachedHandler  http.Handler
)

// DistFS returns an fs.FS rooted inside the "dist" directory.
func DistFS() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}

// Handler returns a cached http.Handler that serves the embedded React SPA.
// It serves static assets from dist/ if they exist.
// If the request is for "/" or "/admin/dashboard" or client-side routes,
// it serves dist/index.html.
// Unknown requests starting with "/admin/" or "/api/" return 404 to avoid
// masking API routing errors with HTML.
func Handler() http.Handler {
	spaHandlerOnce.Do(func() {
		sub, err := fs.Sub(distFS, "dist")
		if err != nil {
			panic(err)
		}
		fileServer := http.FileServer(http.FS(sub))

		cachedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimPrefix(r.URL.Path, "/")

			// Direct match for SPA root or dashboard path
			if path == "" || path == "admin/dashboard" {
				serveIndex(w, sub)
				return
			}

			// Do not mask unknown /admin or /api endpoints with index.html
			if strings.HasPrefix(path, "admin/") || strings.HasPrefix(path, "api/") {
				http.NotFound(w, r)
				return
			}

			// Check if file exists in embedded dist filesystem
			f, err := sub.Open(path)
			if err == nil {
				defer f.Close()
				stat, err := f.Stat()
				if err == nil && !stat.IsDir() {
					fileServer.ServeHTTP(w, r)
					return
				}
			}

			// Client-side routing fallback for non-API paths
			serveIndex(w, sub)
		})
	})

	return cachedHandler
}

func serveIndex(w http.ResponseWriter, sub fs.FS) {
	data, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "SPA index.html not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
