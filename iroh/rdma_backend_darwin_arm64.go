//go:build darwin && arm64

package iroh

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/tmc/go-iroh/netaddr"
)

func init() {
	if os.Getenv("GO_IROH_RDMA_ENABLE") == "1" {
		activeRDMAStreamBackend = darwinRDMAStreamBackend{}
	}
}

type darwinRDMAStreamBackend struct{}

type rdmaStreamResource interface {
	rdmaStreamConnTransport
	localDestination() (rdmaStreamDestination, error)
	connect(context.Context, rdmaStreamDestination, rdmaStreamDestination) error
}

var newRDMAStreamResource = func(ctx context.Context, device string, bufSize int) (rdmaStreamResource, error) {
	return newRDMAStreamResourceTransport(ctx, device, bufSize)
}

func (darwinRDMAStreamBackend) DialStream(ctx context.Context, id uint64, remote netaddr.CustomAddr, opts StreamOptions) (net.Conn, error) {
	if remote.ID() != id {
		return nil, fmt.Errorf("rdma: stream transport id %d, want %d", remote.ID(), id)
	}
	link, err := ParseStreamLinkAddr(remote)
	if err != nil {
		return nil, err
	}
	info, err := parseRDMAStreamDialAddr(link.DialAddr)
	if err != nil {
		return nil, err
	}
	if info.Control == "" {
		return nil, fmt.Errorf("%w: missing control address", ErrRDMAUnsupported)
	}
	rt, err := newRDMAStreamResource(ctx, info.Device, rdmaStreamBufferSize)
	if err != nil {
		return nil, err
	}
	local, err := rt.localDestination()
	if err != nil {
		_ = rt.close()
		return nil, err
	}
	var d net.Dialer
	ctrl, err := d.DialContext(ctx, "tcp", info.Control)
	if err != nil {
		_ = rt.close()
		return nil, fmt.Errorf("rdma: dial control: %w", err)
	}
	defer ctrl.Close()
	if err := writeStreamOpenToken(ctrl, opts.Token); err != nil {
		_ = rt.close()
		return nil, err
	}
	if err := writeRDMAStreamString(ctrl, info.Device); err != nil {
		_ = rt.close()
		return nil, err
	}
	if err := writeRDMAStreamDestination(ctrl, local); err != nil {
		_ = rt.close()
		return nil, err
	}
	remoteDst, err := readRDMAStreamDestination(ctrl)
	if err != nil {
		_ = rt.close()
		return nil, err
	}
	if err := rt.connect(ctx, local, remoteDst); err != nil {
		_ = rt.close()
		return nil, err
	}
	return newRDMAStreamConn(ctx, rt)
}

func (darwinRDMAStreamBackend) ListenStreams(ctx context.Context, id uint64, ln net.Listener, accept func(StreamAccept) error) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-done:
		}
	}()
	defer close(done)
	for {
		ctrl, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("rdma: accept control: %w", err)
		}
		if err := acceptRDMAStreamControl(ctx, id, ctrl, accept); err != nil {
			ctrl.Close()
			return err
		}
		ctrl.Close()
	}
}

func acceptRDMAStreamControl(ctx context.Context, id uint64, ctrl net.Conn, accept func(StreamAccept) error) error {
	tok, err := readStreamOpenToken(ctrl)
	if err != nil {
		return err
	}
	if tok.TransportID != id {
		return fmt.Errorf("rdma: stream token transport id %d, want %d", tok.TransportID, id)
	}
	device, err := readRDMAStreamString(ctrl)
	if err != nil {
		return err
	}
	rt, err := newRDMAStreamResource(ctx, device, rdmaStreamBufferSize)
	if err != nil {
		return err
	}
	local, err := rt.localDestination()
	if err != nil {
		_ = rt.close()
		return err
	}
	remote, err := readRDMAStreamDestination(ctrl)
	if err != nil {
		_ = rt.close()
		return err
	}
	if err := writeRDMAStreamDestination(ctrl, local); err != nil {
		_ = rt.close()
		return err
	}
	if err := rt.connect(ctx, local, remote); err != nil {
		_ = rt.close()
		return err
	}
	conn, err := newRDMAStreamConn(ctx, rt)
	if err != nil {
		_ = rt.close()
		return err
	}
	if err := accept(StreamAccept{Conn: conn, Token: tok}); err != nil {
		conn.Close()
		return err
	}
	return nil
}

const rdmaStreamBufferSize = 1024 * 1024
