package tls

import (
	"bytes"
	"testing"
)

func TestNegotiateALPNServerPreferenceAndBinaryStrings(t *testing.T) {
	primary := "iroh-primary/0"
	binary := string([]byte{'i', 'r', 'o', 'h', '/', 0xff, 0x00, '/', '1'})

	tests := []struct {
		name   string
		server []string
		client []string
		want   string
	}{
		{
			name:   "server preference beats client primary",
			server: []string{binary, primary},
			client: []string{primary, binary},
			want:   binary,
		},
		{
			name:   "binary exact match",
			server: []string{binary},
			client: []string{binary},
			want:   binary,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := negotiateALPN(tt.server, tt.client, true)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal([]byte(got), []byte(tt.want)) {
				t.Errorf("ALPN = % x, want % x", []byte(got), []byte(tt.want))
			}
		})
	}
}
