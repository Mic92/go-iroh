package gossipproto

import (
	"bytes"
	"testing"
)

func FuzzReadFrame(f *testing.F) {
	topic := TopicID(seq32(1))
	msg := TopicMessage{
		Kind: TopicMessageGossip,
		Gossip: PlumtreeMessage{
			Kind:   PlumtreeGossip,
			Gossip: Gossip{ID: MessageIDFromContent([]byte("hello")), Content: []byte("hello")},
		},
	}
	for _, v := range []any{StreamHeader{Topic: topic}, msg} {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, v, DefaultMaxMessageSize); err != nil {
			f.Fatal(err)
		}
		f.Add(buf.Bytes())
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ReadFrame(bytes.NewReader(data), &StreamHeader{}, DefaultMaxMessageSize)
		_ = ReadFrame(bytes.NewReader(data), &TopicMessage{}, DefaultMaxMessageSize)
	})
}
