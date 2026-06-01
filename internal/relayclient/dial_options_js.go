//go:build js

package relayclient

import (
	"net/http"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/internal/relayproto"
)

func dialOptions(_ *http.Client, _ http.Header) *websocket.DialOptions {
	return &websocket.DialOptions{
		Subprotocols: relayproto.SupportedProtocolVersions(),
	}
}
