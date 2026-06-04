package endpointticket_test

import (
	"fmt"

	"github.com/tmc/go-iroh/endpointticket"
)

func ExampleDecode() {
	addr, err := endpointticket.Decode("endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai")
	if err != nil {
		panic(err)
	}
	fmt.Println(addr.ID)
	fmt.Println(len(addr.Addrs()))

	// Output:
	// ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6
	// 2
}
