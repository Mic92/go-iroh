//go:build !js

package relayclient

import (
	"net/http"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/internal/relayproto"
)

func dialOptions(httpClient *http.Client, header http.Header) *websocket.DialOptions {
	return &websocket.DialOptions{
		HTTPClient:   httpClient,
		HTTPHeader:   header,
		Subprotocols: relayproto.SupportedProtocolVersions(),
	}
}
