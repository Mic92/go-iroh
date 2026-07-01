//go:build js

package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"syscall/js"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

func main() {
	go func() {
		if err := run(); err != nil {
			setStatus("fail", err.Error())
			return
		}
		setStatus("pass", "relay-only browser echo passed")
	}()
	select {}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := relayURLFromLocation()
	if err != nil {
		return err
	}
	relayURL, err := netaddr.ParseRelayURL(raw)
	if err != nil {
		return fmt.Errorf("parse relay url: %w", err)
	}
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))

	const alpn = "iroh-wasm-relaytest/0"
	serverKey, err := key.GenerateSecretKey()
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}
	server, err := iroh.Bind(ctx,
		iroh.WithSecretKey(serverKey),
		iroh.WithALPNs(alpn),
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
	)
	if err != nil {
		return fmt.Errorf("bind server: %w", err)
	}
	defer server.Shutdown(ctx)

	client, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
	)
	if err != nil {
		return fmt.Errorf("bind client: %w", err)
	}
	defer client.Shutdown(ctx)

	if err := server.Online(ctx); err != nil {
		return fmt.Errorf("server online: %w", err)
	}
	if err := client.Online(ctx); err != nil {
		return fmt.Errorf("client online: %w", err)
	}

	errc := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			errc <- fmt.Errorf("accept: %w", err)
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			errc <- fmt.Errorf("accept stream: %w", err)
			return
		}
		data, err := io.ReadAll(stream)
		if err != nil {
			errc <- fmt.Errorf("read stream: %w", err)
			return
		}
		if _, err := stream.Write(data); err != nil {
			errc <- fmt.Errorf("write echo: %w", err)
			return
		}
		errc <- stream.Close()
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL)
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		return fmt.Errorf("connect relay-only: %w", err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	const msg = "hello from browser wasm over relay"
	if _, err := stream.Write([]byte(msg)); err != nil {
		return fmt.Errorf("write stream: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close stream: %w", err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if string(got) != msg {
		return fmt.Errorf("echo = %q, want %q", got, msg)
	}
	if err := <-errc; err != nil {
		return err
	}
	return nil
}

func relayURLFromLocation() (string, error) {
	href := js.Global().Get("location").Get("href").String()
	u, err := url.Parse(href)
	if err != nil {
		return "", fmt.Errorf("parse location: %w", err)
	}
	raw := u.Query().Get("relay")
	if raw == "" {
		return "", fmt.Errorf("missing relay query")
	}
	return raw, nil
}

func setStatus(status, detail string) {
	doc := js.Global().Get("document")
	body := doc.Get("body")
	body.Set("textContent", detail)
	body.Call("setAttribute", "data-status", status)
	body.Call("setAttribute", "data-detail", detail)
}
