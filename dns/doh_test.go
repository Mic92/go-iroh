package dns

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDoHLookuperLookupTXT(t *testing.T) {
	const wantName = "_iroh.example."
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/dns-message" {
			t.Errorf("Content-Type = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		name := parseQuestionName(t, body)
		if name.String() != wantName {
			t.Errorf("query name = %q, want %q", name.String(), wantName)
		}
		resp := packTXTResponse(t, name, []string{"relay=https://relay.example/"})
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(resp)
	}))
	defer ts.Close()

	got, err := (&DoHLookuper{URL: ts.URL}).LookupTXT(context.Background(), wantName)
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(got) != 1 || got[0] != "relay=https://relay.example/" {
		t.Fatalf("TXT = %q", got)
	}
}

func parseQuestionName(t *testing.T, msg []byte) dnsmessage.Name {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}
	if q.Type != dnsmessage.TypeTXT || q.Class != dnsmessage.ClassINET {
		t.Fatalf("question = %+v, want TXT IN", q)
	}
	return q.Name
}

func packTXTResponse(t *testing.T, name dnsmessage.Name, txt []string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RecursionAvailable: true})
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := b.TXTResource(dnsmessage.ResourceHeader{
		Name:  name,
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
		TTL:   30,
	}, dnsmessage.TXTResource{TXT: txt}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}
