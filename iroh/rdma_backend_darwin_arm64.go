//go:build darwin && arm64

package iroh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

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
	bufSize := rdmaStreamBufferSize()
	var d net.Dialer
	ctrl, err := d.DialContext(ctx, "tcp", info.Control)
	if err != nil {
		return nil, fmt.Errorf("rdma: dial control: %w", err)
	}
	defer ctrl.Close()
	if err := setRDMAStreamControlDeadline(ctx, ctrl); err != nil {
		return nil, err
	}
	if err := writeStreamOpenToken(ctrl, opts.Token); err != nil {
		return nil, err
	}
	if err := writeRDMAStreamString(ctrl, info.Device); err != nil {
		return nil, err
	}
	rt, err := newRDMAStreamResource(ctx, info.Device, bufSize)
	if err != nil {
		return nil, err
	}
	local, err := rt.localDestination()
	if err != nil {
		_ = rt.close()
		return nil, err
	}
	if err := writeRDMAStreamDestination(ctrl, local); err != nil {
		_ = rt.close()
		return nil, err
	}
	if err := writeRDMAStreamFramePayload(ctrl, rdmaStreamPayloadForBuffer(bufSize)); err != nil {
		_ = rt.close()
		return nil, err
	}
	remoteDst, err := readRDMAStreamDestination(ctrl)
	if err != nil {
		_ = rt.close()
		return nil, err
	}
	remotePayload, err := readRDMAStreamFramePayload(ctrl)
	if err != nil {
		_ = rt.close()
		return nil, err
	}
	if err := rt.connect(ctx, local, remoteDst); err != nil {
		_ = rt.close()
		return nil, err
	}
	conn, err := newRDMAStreamConnWithMaxPayload(ctx, rt, min(rdmaStreamPayloadForBuffer(bufSize), remotePayload))
	if err != nil {
		_ = rt.close()
		return nil, err
	}
	if err := dialRDMAStreamWarmupReady(ctrl); err != nil {
		conn.Close()
		return nil, err
	}
	if err := warmupRDMAStreamConn(ctx, conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
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
	if err := setRDMAStreamControlDeadline(ctx, ctrl); err != nil {
		return err
	}
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
	bufSize := rdmaStreamBufferSize()
	rt, err := newRDMAStreamResource(ctx, device, bufSize)
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
	remotePayload, err := readRDMAStreamFramePayload(ctrl)
	if err != nil {
		_ = rt.close()
		return err
	}
	if err := writeRDMAStreamDestination(ctrl, local); err != nil {
		_ = rt.close()
		return err
	}
	if err := writeRDMAStreamFramePayload(ctrl, rdmaStreamPayloadForBuffer(bufSize)); err != nil {
		_ = rt.close()
		return err
	}
	if err := rt.connect(ctx, local, remote); err != nil {
		_ = rt.close()
		return err
	}
	conn, err := newRDMAStreamConnWithMaxPayload(ctx, rt, min(rdmaStreamPayloadForBuffer(bufSize), remotePayload))
	if err != nil {
		_ = rt.close()
		return err
	}
	if err := acceptRDMAStreamWarmupReady(ctrl); err != nil {
		conn.Close()
		return err
	}
	if err := warmupRDMAStreamConn(ctx, conn); err != nil {
		conn.Close()
		return err
	}
	if err := accept(StreamAccept{Conn: conn, Token: tok}); err != nil {
		conn.Close()
		return err
	}
	return nil
}

func rdmaStreamBufferSize() int {
	s := os.Getenv("GO_IROH_RDMA_BUFFER_SIZE")
	if s == "" {
		return defaultRDMAStreamBufferSize
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < rdmaStreamFrameHeaderSize+1 {
		return defaultRDMAStreamBufferSize
	}
	return n
}

func rdmaStreamPayloadForBuffer(n int) int {
	return rdmaStreamSlotPayload(n, rdmaStreamRecvSlotCount(n))
}

func setRDMAStreamControlDeadline(ctx context.Context, ctrl net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := ctrl.SetDeadline(deadline); err != nil {
			return fmt.Errorf("rdma: set control deadline: %w", err)
		}
	}
	return nil
}

func dialRDMAStreamWarmupReady(ctrl net.Conn) error {
	if _, err := ctrl.Write([]byte{0}); err != nil {
		return fmt.Errorf("rdma: warmup ready write: %w", err)
	}
	var b [1]byte
	if _, err := io.ReadFull(ctrl, b[:]); err != nil {
		return fmt.Errorf("rdma: warmup ready read: %w", err)
	}
	return nil
}

func acceptRDMAStreamWarmupReady(ctrl net.Conn) error {
	var b [1]byte
	if _, err := io.ReadFull(ctrl, b[:]); err != nil {
		return fmt.Errorf("rdma: warmup ready read: %w", err)
	}
	if _, err := ctrl.Write([]byte{0}); err != nil {
		return fmt.Errorf("rdma: warmup ready write: %w", err)
	}
	return nil
}

func warmupRDMAStreamConn(ctx context.Context, conn *rdmaStreamConn) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("rdma: warmup stream: %w", err)
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return fmt.Errorf("rdma: warmup stream write: %w", err)
	}
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		return fmt.Errorf("rdma: warmup stream read: %w", err)
	}
	return nil
}

const defaultRDMAStreamBufferSize = rdmaStreamMaxRecvSlots * (rdmaStreamMinSlotPayload + rdmaStreamFrameHeaderSize)
