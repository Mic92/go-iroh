package relayserver_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/tmc/go-iroh/relayserver"
)

func ExampleNew() {
	srv := httptest.NewServer(relayserver.New())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println(resp.StatusCode)

	// Output:
	// 404
}
