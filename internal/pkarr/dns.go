package pkarr

import (
	"fmt"

	"golang.org/x/net/dns/dnsmessage"
)

// txtRecord is a parsed TXT resource record: its owner name and concatenated
// character-strings.
type txtRecord struct {
	name string
	txt  string
}

// buildTxtPacket builds a compressed DNS reply packet containing one TXT answer
// record per value, all under name, with the given TTL. This is the
// regeneratable core that produces the DNS wire bytes the signature covers.
func buildTxtPacket(name string, values []string, ttl uint32) ([]byte, error) {
	dnsName, err := dnsmessage.NewName(ensureFQDN(name))
	if err != nil {
		return nil, fmt.Errorf("invalid name %q: %w", name, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, v := range values {
		hdr := dnsmessage.ResourceHeader{
			Name:  dnsName,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		}
		if err := b.TXTResource(hdr, dnsmessage.TXTResource{TXT: splitTxt(v)}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// parsePacket parses a DNS packet and returns its TXT answer records.
func parsePacket(encoded []byte) ([]txtRecord, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(encoded); err != nil {
		return nil, err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var out []txtRecord
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
		r, err := p.TXTResource()
		if err != nil {
			return nil, err
		}
		out = append(out, txtRecord{name: h.Name.String(), txt: joinTxt(r.TXT)})
	}
	return out, nil
}

// splitTxt splits a value into DNS character-strings of at most 255 bytes. iroh
// values are short (UserData is capped at 245), so this is usually a single
// element, but the split keeps long values valid on the wire.
func splitTxt(v string) []string {
	if len(v) == 0 {
		return []string{""}
	}
	var out []string
	for len(v) > 255 {
		out = append(out, v[:255])
		v = v[255:]
	}
	return append(out, v)
}

// joinTxt concatenates the character-strings of a TXT record, matching
// simple_dns's String::try_from(TXT) used by the Rust reference.
func joinTxt(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	var s string
	for _, p := range parts {
		s += p
	}
	return s
}

func ensureFQDN(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}
