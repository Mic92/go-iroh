// Package pkarrserver implements the HTTP pkarr relay surface used by iroh DNS.
package pkarrserver

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Server stores pkarr signed packets in memory and serves them over HTTP.
type Server struct {
	mu    sync.Mutex
	store map[string][]byte
}

// New returns an empty pkarr server.
func New() *Server {
	return &Server{store: make(map[string][]byte)}
}

// ServeHTTP handles PUT and GET of signed packets at /pkarr/<key> or /<key>.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/")
	key = strings.TrimPrefix(key, "pkarr/")
	if key == "" || strings.Contains(key, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024*1024))
		if err != nil {
			http.Error(w, "packet too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.mu.Lock()
		s.store[key] = bytes.Clone(body)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		s.mu.Lock()
		body, ok := s.store[key]
		body = bytes.Clone(body)
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pkarr-signed-packet")
		w.Write(body)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
