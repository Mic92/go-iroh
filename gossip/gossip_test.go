package gossip_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestSenderHandlerLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var topic gossip.TopicID
	copy(topic[:], "topic")
	want := []gossip.Message{{
		Topic: topic,
		Message: gossip.TopicMessage{
			Kind: gossipproto.TopicMessageSwarm,
			Swarm: gossipproto.HyparviewMessage{
				Kind: gossipproto.HyparviewJoin,
			},
		},
	}}
	var otherTopic gossip.TopicID
	copy(otherTopic[:], "other")
	want = append(want, gossip.Message{
		Topic: otherTopic,
		Message: gossip.TopicMessage{
			Kind: gossipproto.TopicMessageSwarm,
			Swarm: gossipproto.HyparviewMessage{
				Kind: gossipproto.HyparviewNeighbor,
				Neighbor: gossipproto.Neighbor{
					Priority: gossipproto.PriorityHigh,
				},
			},
		},
	})

	gotc := make(chan gossip.Message, len(want))
	fromc := make(chan key.EndpointID, len(want))

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		gossip.ALPN: &gossip.Handler{
			Handle: func(ctx context.Context, from key.EndpointID, msg gossip.Message) error {
				fromc <- from
				gotc <- msg
				return nil
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, gossip.ALPN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	sender := gossip.NewSender(conn, 0)
	for _, msg := range want {
		if err := sender.Send(ctx, msg); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if err := sender.Close(); err != nil {
		t.Fatalf("close sender: %v", err)
	}

	got := make(map[gossip.TopicID]gossip.Message)
	for range want {
		select {
		case msg := <-gotc:
			got[msg.Topic] = msg
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for _, msg := range want {
		if got[msg.Topic].Message.Kind != msg.Message.Kind || got[msg.Topic].Message.Swarm.Kind != msg.Message.Swarm.Kind {
			t.Fatalf("message for topic %x = %+v, want %+v", msg.Topic, got[msg.Topic], msg)
		}
	}

	for range want {
		select {
		case from := <-fromc:
			if !from.Equal(client.ID()) {
				t.Fatalf("from = %s, want %s", from, client.ID())
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
