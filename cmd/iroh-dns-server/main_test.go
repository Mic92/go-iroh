package main

import (
	"net/http"
	"testing"
)

func TestHTTPServerTimeouts(t *testing.T) {
	srv := newHTTPServer(":0", http.NotFoundHandler())
	if srv.ReadHeaderTimeout != httpReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, httpReadHeaderTimeout)
	}
	if srv.ReadTimeout != httpReadTimeout {
		t.Fatalf("ReadTimeout = %v, want %v", srv.ReadTimeout, httpReadTimeout)
	}
	if srv.WriteTimeout != httpWriteTimeout {
		t.Fatalf("WriteTimeout = %v, want %v", srv.WriteTimeout, httpWriteTimeout)
	}
	if srv.IdleTimeout != httpIdleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", srv.IdleTimeout, httpIdleTimeout)
	}
}
