package pkarrserver

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerPutGet(t *testing.T) {
	ts := httptest.NewServer(New())
	defer ts.Close()

	body := []byte("signed packet")
	req, err := http.NewRequest(http.MethodPut, ts.URL+"/pkarr/example", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	resp, err = ts.Client().Get(ts.URL + "/pkarr/example")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(got) != string(body) {
		t.Fatalf("GET status/body = %d %q, want 200 %q", resp.StatusCode, got, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/x-pkarr-signed-packet" {
		t.Fatalf("Content-Type = %q", got)
	}
}
