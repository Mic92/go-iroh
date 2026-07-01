//go:build js

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"syscall/js"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/docs"
	"github.com/tmc/go-iroh/gossip"
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

	values, err := locationQuery()
	if err != nil {
		return err
	}
	relayURL, err := netaddr.ParseRelayURL(values.Get("relay"))
	if err != nil {
		return fmt.Errorf("parse relay url: %w", err)
	}
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))

	switch values.Get("mode") {
	case "blob-native":
		return runBlobNative(ctx, values, relayURL, mode)
	case "docs-native":
		return runDocsNative(ctx, values, relayURL, mode)
	case "gossip-browser":
		return runGossipBrowser(ctx, relayURL, mode)
	case "browser-native":
		return runBrowserNative(ctx, values, relayURL, mode)
	default:
		return runBrowserBrowser(ctx, relayURL, mode)
	}
}

func runBrowserBrowser(ctx context.Context, relayURL netaddr.RelayURL, mode relay.Mode) error {
	const alpn = "iroh-wasm-relaytest/2"
	serverKey, err := key.GenerateSecretKey()
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}
	server, err := iroh.Bind(ctx,
		iroh.WithSecretKey(serverKey),
		iroh.WithALPNs(alpn),
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAlive()),
	)
	if err != nil {
		return fmt.Errorf("bind server: %w", err)
	}
	defer server.Shutdown(ctx)

	client, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAlive()),
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
		errc <- serveFrames(ctx, stream)
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
	if err := exchangeFrames(ctx, stream); err != nil {
		return err
	}
	if err := <-errc; err != nil {
		return err
	}
	return nil
}

func runBrowserNative(ctx context.Context, values url.Values, relayURL netaddr.RelayURL, mode relay.Mode) error {
	const alpn = "iroh-wasm-native/2"
	peer := values.Get("peer")
	if peer == "" {
		return fmt.Errorf("missing peer query")
	}
	id, err := key.ParseEndpointID(peer)
	if err != nil {
		return fmt.Errorf("parse peer id: %w", err)
	}
	client, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAlive()),
	)
	if err != nil {
		return fmt.Errorf("bind browser client: %w", err)
	}
	defer client.Shutdown(ctx)
	if err := client.Online(ctx); err != nil {
		return fmt.Errorf("browser client online: %w", err)
	}
	addr := netaddr.NewEndpointAddr(id).WithRelayURL(relayURL)
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		return fmt.Errorf("connect native relay-only: %w", err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open native stream: %w", err)
	}
	if err := exchangeFrames(ctx, stream); err != nil {
		return err
	}
	return nil
}

func runDocsNative(ctx context.Context, values url.Values, relayURL netaddr.RelayURL, mode relay.Mode) error {
	peer := values.Get("peer")
	if peer == "" {
		return fmt.Errorf("missing peer query")
	}
	id, err := key.ParseEndpointID(peer)
	if err != nil {
		return fmt.Errorf("parse peer id: %w", err)
	}
	namespace := docs.NewNamespaceSecret(repeat32(0xb2))
	author := docs.NewAuthor(repeat32(0xa1))
	serverEntry := docSignedEntry(namespace, author, "server", "server-data", 1)
	clientEntry := docSignedEntry(namespace, author, "client", "client-data", 1)
	clientStore := docs.NewMemoryStore()
	clientStore.Put(clientEntry)

	client, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAlive()),
	)
	if err != nil {
		return fmt.Errorf("bind docs client: %w", err)
	}
	defer client.Shutdown(ctx)
	if err := client.Online(ctx); err != nil {
		return fmt.Errorf("docs client online: %w", err)
	}
	addr := netaddr.NewEndpointAddr(id).WithRelayURL(relayURL)
	outcome, err := docs.Sync(ctx, client, addr, namespace.ID(), clientStore, nil, docs.DefaultSyncConfig())
	if err != nil {
		return fmt.Errorf("docs sync: %w", err)
	}
	if outcome.NumSent == 0 || outcome.NumRecv == 0 {
		return fmt.Errorf("docs sync outcome = %+v, want sent and received entries", outcome)
	}
	got, ok := clientStore.GetExact(namespace.ID(), author.ID(), []byte("server"), false)
	if !ok {
		return fmt.Errorf("docs client missing server entry")
	}
	if got.Entry.Compare(serverEntry.Entry) != 0 {
		return fmt.Errorf("docs server entry mismatch")
	}
	return nil
}

func runGossipBrowser(ctx context.Context, relayURL netaddr.RelayURL, mode relay.Mode) error {
	var topic gossip.TopicID
	copy(topic[:], "wasm-gossip-relay")

	server, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAlive()),
	)
	if err != nil {
		return fmt.Errorf("bind gossip server: %w", err)
	}
	defer server.Shutdown(ctx)
	serverGossip := gossip.NewGossip(server)
	serverRouter, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		gossip.ALPN: serverGossip.Handler(),
	}, nil)
	if err != nil {
		return fmt.Errorf("server gossip router: %w", err)
	}
	defer serverRouter.Shutdown(ctx)

	client, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAlive()),
	)
	if err != nil {
		return fmt.Errorf("bind gossip client: %w", err)
	}
	defer client.Shutdown(ctx)
	clientGossip := gossip.NewGossip(client)
	clientRouter, err := iroh.NewRouter(client, map[string]iroh.ProtocolHandler{
		gossip.ALPN: clientGossip.Handler(),
	}, nil)
	if err != nil {
		return fmt.Errorf("client gossip router: %w", err)
	}
	defer clientRouter.Shutdown(ctx)

	if err := server.Online(ctx); err != nil {
		return fmt.Errorf("gossip server online: %w", err)
	}
	if err := client.Online(ctx); err != nil {
		return fmt.Errorf("gossip client online: %w", err)
	}
	serverTopic, err := serverGossip.Subscribe(ctx, topic, nil)
	if err != nil {
		return fmt.Errorf("server subscribe: %w", err)
	}
	defer serverTopic.Close()
	clientTopic, err := clientGossip.SubscribeAndJoin(ctx, topic, []netaddr.EndpointAddr{
		netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL),
	})
	if err != nil {
		return fmt.Errorf("client subscribe join: %w", err)
	}
	defer clientTopic.Close()

	const msg = "hello gossip from browser"
	if err := clientTopic.Broadcast(ctx, []byte(msg)); err != nil {
		return fmt.Errorf("gossip broadcast: %w", err)
	}
	for {
		ev, err := nextGossipEvent(ctx, serverTopic)
		if err != nil {
			return err
		}
		if ev.Kind != gossip.Received {
			continue
		}
		if string(ev.Content) != msg {
			return fmt.Errorf("gossip content = %q, want %q", ev.Content, msg)
		}
		if !ev.DeliveredFrom.Equal(client.ID()) {
			return fmt.Errorf("gossip delivered from %s, want %s", ev.DeliveredFrom, client.ID())
		}
		return nil
	}
}

func runBlobNative(ctx context.Context, values url.Values, relayURL netaddr.RelayURL, mode relay.Mode) error {
	peer := values.Get("peer")
	if peer == "" {
		return fmt.Errorf("missing peer query")
	}
	id, err := key.ParseEndpointID(peer)
	if err != nil {
		return fmt.Errorf("parse peer id: %w", err)
	}
	size, err := strconv.Atoi(values.Get("size"))
	if err != nil || size <= 0 {
		return fmt.Errorf("invalid size query %q", values.Get("size"))
	}
	want := blobPayload(size)
	hash := blobs.NewHash(want)

	client, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAlive()),
	)
	if err != nil {
		return fmt.Errorf("bind blob client: %w", err)
	}
	defer client.Shutdown(ctx)
	if err := client.Online(ctx); err != nil {
		return fmt.Errorf("blob client online: %w", err)
	}
	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(id).WithRelayURL(relayURL), blobs.ALPN)
	if err != nil {
		return fmt.Errorf("connect blob provider: %w", err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open blob stream: %w", err)
	}
	got, err := blobs.GetBlobBytes(ctx, stream, hash)
	if err != nil {
		return fmt.Errorf("get blob: %w", err)
	}
	if string(got) != string(want) {
		return fmt.Errorf("blob length = %d, want %d", len(got), len(want))
	}
	if gotHash := blobs.NewHash(got); gotHash != hash {
		return fmt.Errorf("blob hash = %s, want %s", gotHash, hash)
	}
	return nil
}

func nextGossipEvent(ctx context.Context, topic *gossip.Topic) (gossip.Event, error) {
	type result struct {
		ev  gossip.Event
		err error
	}
	ch := make(chan result, 1)
	go func() {
		for ev, err := range topic.Events() {
			ch <- result{ev: ev, err: err}
			return
		}
		ch <- result{err: fmt.Errorf("gossip topic closed")}
	}()
	select {
	case res := <-ch:
		return res.ev, res.err
	case <-ctx.Done():
		return gossip.Event{}, ctx.Err()
	}
}

func shortKeepAlive() *iroh.QUICTransportConfig {
	return &iroh.QUICTransportConfig{
		KeepAlivePeriod: 200 * time.Millisecond,
		MaxIdleTimeout:  5 * time.Second,
	}
}

func serveFrames(ctx context.Context, stream io.ReadWriteCloser) error {
	for i := 0; i < 4; i++ {
		got, err := readFrame(stream)
		if err != nil {
			return fmt.Errorf("server read frame %d: %w", i, err)
		}
		if want := payload(i); string(got) != string(want) {
			return fmt.Errorf("server frame %d mismatch", i)
		}
		if err := writeFrame(stream, payload(100+i)); err != nil {
			return fmt.Errorf("server write frame %d: %w", i, err)
		}
		if i == 1 {
			if err := sleepContext(ctx, 600*time.Millisecond); err != nil {
				return err
			}
		}
	}
	return stream.Close()
}

func exchangeFrames(ctx context.Context, stream io.ReadWriteCloser) error {
	for i := 0; i < 4; i++ {
		if err := writeFrame(stream, payload(i)); err != nil {
			return fmt.Errorf("client write frame %d: %w", i, err)
		}
		got, err := readFrame(stream)
		if err != nil {
			return fmt.Errorf("client read frame %d: %w", i, err)
		}
		if want := payload(100 + i); string(got) != string(want) {
			return fmt.Errorf("client frame %d mismatch", i)
		}
	}
	return stream.Close()
}

func payload(seed int) []byte {
	p := make([]byte, 64*1024+seed%17)
	for i := range p {
		p[i] = byte(seed + i*31)
	}
	return p
}

func blobPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(11 + i*17)
	}
	return p
}

func docSignedEntry(namespace docs.NamespaceSecret, author docs.Author, keyName, data string, timestamp uint64) docs.SignedEntry {
	hash := blobs.NewHash([]byte(data))
	id := docs.NewRecordIdentifier(namespace.ID(), author.ID(), []byte(keyName))
	return docs.NewSignedEntry(docs.NewEntry(id, docs.NewRecord(hash, uint64(len(data)), timestamp)), namespace, author)
}

func repeat32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func writeFrame(w io.Writer, p []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func locationQuery() (url.Values, error) {
	href := js.Global().Get("location").Get("href").String()
	u, err := url.Parse(href)
	if err != nil {
		return nil, fmt.Errorf("parse location: %w", err)
	}
	values := u.Query()
	if values.Get("relay") == "" {
		return nil, fmt.Errorf("missing relay query")
	}
	return values, nil
}

func setStatus(status, detail string) {
	doc := js.Global().Get("document")
	body := doc.Get("body")
	body.Set("textContent", detail)
	body.Call("setAttribute", "data-status", status)
	body.Call("setAttribute", "data-detail", detail)
}
