package gossipproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	topic := TopicID(seq32(1))
	msg := Message{
		Topic: topic,
		Message: TopicMessage{
			Kind: TopicMessageGossip,
			Gossip: PlumtreeMessage{
				Kind:   PlumtreeGossip,
				Gossip: Gossip{ID: MessageIDFromContent([]byte("hello")), Content: []byte("hello")},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, StreamHeader{Topic: topic}, DefaultMaxMessageSize); err != nil {
		t.Fatalf("WriteFrame header: %v", err)
	}
	if err := WriteFrame(&buf, msg.Message, DefaultMaxMessageSize); err != nil {
		t.Fatalf("WriteFrame message: %v", err)
	}

	if got := binary.BigEndian.Uint32(buf.Bytes()[:4]); got != 32 {
		t.Fatalf("header length = %d, want 32", got)
	}
	var gotHeader StreamHeader
	if err := ReadFrame(&buf, &gotHeader, DefaultMaxMessageSize); err != nil {
		t.Fatalf("ReadFrame header: %v", err)
	}
	if gotHeader != (StreamHeader{Topic: topic}) {
		t.Fatalf("header = %#v, want %#v", gotHeader, StreamHeader{Topic: topic})
	}
	var gotMessage TopicMessage
	if err := ReadFrame(&buf, &gotMessage, DefaultMaxMessageSize); err != nil {
		t.Fatalf("ReadFrame message: %v", err)
	}
	if !reflect.DeepEqual(gotMessage, msg.Message) {
		t.Fatalf("message = %#v, want %#v", gotMessage, msg.Message)
	}
}

func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, StreamHeader{}, 32)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrame err = %v, want ErrFrameTooLarge", err)
	}

	var raw bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 32)
	raw.Write(hdr[:])
	raw.Write(make([]byte, 32))
	err = ReadFrame(&raw, &StreamHeader{}, 31)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame err = %v, want ErrFrameTooLarge", err)
	}
}

func TestFrameShortRead(t *testing.T) {
	err := ReadFrame(bytes.NewReader([]byte{0, 0}), &StreamHeader{}, DefaultMaxMessageSize)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short length err = %v, want io.ErrUnexpectedEOF", err)
	}

	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 8)
	buf.Write(hdr[:])
	buf.Write([]byte{1, 2})
	err = ReadFrame(&buf, &StreamHeader{}, DefaultMaxMessageSize)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short body err = %v, want io.ErrUnexpectedEOF", err)
	}
}
