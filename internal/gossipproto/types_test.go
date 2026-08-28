package gossipproto

import (
	"encoding/hex"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/postcard"
)

func TestRustWireVectors(t *testing.T) {
	topic := TopicID(seq32(0))
	peer := PeerID(seq32(0x40))
	msgid := MessageID(seq32(0xa0))
	data := PeerData{1, 2, 3}
	peerInfo := PeerInfo{ID: peer, Data: &data}

	tests := []struct {
		name string
		v    any
		hex  string
	}{
		{
			name: "topic join some",
			v: Message{
				Topic: topic,
				Message: TopicMessage{
					Kind:  TopicMessageSwarm,
					Swarm: HyparviewMessage{Kind: HyparviewJoin, Join: &data},
				},
			},
			hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000103010203",
		},
		{
			name: "topic neighbor",
			v: Message{
				Topic: topic,
				Message: TopicMessage{
					Kind: TopicMessageSwarm,
					Swarm: HyparviewMessage{
						Kind:     HyparviewNeighbor,
						Neighbor: Neighbor{Priority: PriorityHigh, Data: &data},
					},
				},
			},
			hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0004000103010203",
		},
		{
			name: "forward join",
			v: HyparviewMessage{
				Kind:        HyparviewForwardJoin,
				ForwardJoin: ForwardJoin{Peer: peerInfo, Ttl: 7},
			},
			hex: "01404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f010301020307",
		},
		{
			name: "shuffle",
			v: HyparviewMessage{
				Kind:    HyparviewShuffle,
				Shuffle: Shuffle{Origin: peer, Nodes: []PeerInfo{peerInfo}, Ttl: 9},
			},
			hex: "02404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f01404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f010301020309",
		},
		{
			name: "shuffle reply",
			v: HyparviewMessage{
				Kind:         HyparviewShuffleReply,
				ShuffleReply: ShuffleReply{Nodes: []PeerInfo{peerInfo}},
			},
			hex: "0301404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0103010203",
		},
		{
			name: "disconnect",
			v:    HyparviewMessage{Kind: HyparviewDisconnect, Disconnect: Disconnect{Alive: true}},
			hex:  "050100",
		},
		{
			name: "topic prune",
			v: Message{
				Topic: topic,
				Message: TopicMessage{
					Kind:   TopicMessageGossip,
					Gossip: PlumtreeMessage{Kind: PlumtreePrune},
				},
			},
			hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0101",
		},
		{
			name: "plum gossip",
			v: PlumtreeMessage{
				Kind: PlumtreeGossip,
				Gossip: Gossip{
					ID:      msgid,
					Content: []byte{9, 8, 7},
					Scope:   DeliveryScope{Kind: DeliveryScopeSwarm, Round: 2},
				},
			},
			hex: "00a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf030908070002",
		},
		{
			name: "plum graft none",
			v:    PlumtreeMessage{Kind: PlumtreeGraft, Graft: Graft{Round: 3}},
			hex:  "020003",
		},
		{
			name: "plum graft some",
			v:    PlumtreeMessage{Kind: PlumtreeGraft, Graft: Graft{ID: &msgid, Round: 3}},
			hex:  "0201a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf03",
		},
		{
			name: "plum ihave",
			v:    PlumtreeMessage{Kind: PlumtreeIHave, IHave: []IHave{{ID: msgid, Round: 4}}},
			hex:  "0301a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf04",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := postcard.Marshal(tt.v)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if hex.EncodeToString(got) != tt.hex {
				t.Fatalf("Marshal = %x, want %s", got, tt.hex)
			}
			dst := reflect.New(reflect.TypeOf(tt.v)).Interface()
			if err := postcard.Unmarshal(got, dst); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(dst).Elem().Interface(), tt.v) {
				t.Fatalf("round trip = %#v, want %#v", reflect.ValueOf(dst).Elem().Interface(), tt.v)
			}
		})
	}
}

func seq32(start byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

// testRand returns a generator seeded from GOIROH_TEST_SEED, or from the clock
// when that is unset. The state machines otherwise seed themselves from the
// clock with no way to recover the seed, so a failure could not be rerun
// against the input that produced it. t.Log reports the seed and the command
// to replay it, and go test prints that only for tests that fail.
func testRand(t *testing.T) *rand.Rand {
	t.Helper()
	seed := time.Now().UnixNano()
	if s := os.Getenv("GOIROH_TEST_SEED"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("GOIROH_TEST_SEED=%q: %v", s, err)
		}
		seed = n
	}
	t.Logf("rand seed %d; replay with GOIROH_TEST_SEED=%d go test -run %s ./internal/gossipproto/", seed, seed, t.Name())
	return rand.New(rand.NewSource(seed))
}
