package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// DoHLookuper resolves TXT records using DNS-over-HTTPS.
//
// It sends RFC 8484 POST requests with Content-Type application/dns-message.
// The zero value is not usable; create one with [NewDoHLookuper].
type DoHLookuper struct {
	// URL is the DNS-over-HTTPS endpoint.
	URL string
	// HTTPClient sends requests. If nil, [http.DefaultClient] is used.
	HTTPClient *http.Client
}

// NewDoHLookuper returns a TXT lookuper backed by a DNS-over-HTTPS endpoint.
func NewDoHLookuper(url string) *DoHLookuper {
	return &DoHLookuper{URL: url}
}

// LookupTXT resolves name as TXT using DNS-over-HTTPS.
func (l *DoHLookuper) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if l == nil || l.URL == "" {
		return nil, fmt.Errorf("doh: missing endpoint url")
	}
	msg, err := packTXTQuery(name)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.URL, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := l.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh lookup %q: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("doh lookup %q: http status %s", name, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("doh lookup %q: read response: %w", name, err)
	}
	txt, err := unpackTXTResponse(body)
	if err != nil {
		return nil, fmt.Errorf("doh lookup %q: %w", name, err)
	}
	return txt, nil
}

func packTXTQuery(name string) ([]byte, error) {
	dnsName, err := dnsmessage.NewName(ensureTrailingDot(name))
	if err != nil {
		return nil, fmt.Errorf("doh: bad name %q: %w", name, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsName,
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func unpackTXTResponse(msg []byte) ([]string, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil, err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var out []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Type != dnsmessage.TypeTXT {
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			return nil, err
		}
		out = append(out, strings.Join(txt.TXT, ""))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no TXT answers")
	}
	return out, nil
}
