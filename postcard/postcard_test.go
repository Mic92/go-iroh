package postcard_test

import (
	"reflect"
	"testing"

	"github.com/tmc/go-iroh/postcard"
)

func TestRoundTrip(t *testing.T) {
	type value struct {
		N    uint64
		Name string
		Data []byte
	}
	want := value{N: 300, Name: "iroh", Data: []byte{1, 2, 3}}
	b, err := postcard.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got value
	if err := postcard.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}
