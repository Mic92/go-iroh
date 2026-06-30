package metrics

import (
	"context"
	"net"
	"net/http"
)

const openMetricsContentType = "application/openmetrics-text; version=1.0.0; charset=utf-8"

// Handler returns an HTTP handler serving r at /metrics.
func Handler(r *Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", openMetricsContentType)
		if req.Method == http.MethodHead {
			return
		}
		if err := r.WriteOpenMetrics(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	return mux
}

// Server is a small HTTP server for OpenMetrics scraping.
type Server struct {
	server *http.Server
}

// NewServer returns a metrics HTTP server bound to addr.
func NewServer(addr string, r *Registry) *Server {
	return &Server{
		server: &http.Server{
			Addr:    addr,
			Handler: Handler(r),
		},
	}
}

// ListenAndServe serves metrics until the server is shut down.
func (s *Server) ListenAndServe() error {
	if s == nil || s.server == nil {
		return http.ErrServerClosed
	}
	return s.server.ListenAndServe()
}

// Serve serves metrics on l until the server is shut down.
func (s *Server) Serve(l net.Listener) error {
	if s == nil || s.server == nil {
		return http.ErrServerClosed
	}
	return s.server.Serve(l)
}

// Shutdown gracefully shuts down the metrics server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}
