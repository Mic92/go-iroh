package blobs_test

import (
	"fmt"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func Example() {
	id, _ := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	hash, _ := blobs.ParseHash("0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072")
	ticket := blobs.NewTicket(netaddr.NewEndpointAddr(id), hash, blobs.Raw)

	parsed, _ := blobs.ParseTicket(ticket.String())
	fmt.Println(parsed.Hash() == hash, parsed.Format())
	// Output: true Raw
}
