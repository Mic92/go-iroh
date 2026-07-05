//go:build !darwin

package iroh

func platformTransportInterfaceClass(name string) (TransportLinkClass, bool) {
	return "", false
}
