package iroh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// rdmaStreamDestination is the queue-pair metadata exchanged before an RDMA
// stream can move data.
type rdmaStreamDestination struct {
	LID       uint16
	QPN       uint32
	PSN       uint32
	GIDIndex  uint8
	GID       [16]byte
	ActiveMTU int32
}

func writeRDMAStreamDestination(w io.Writer, dst rdmaStreamDestination) error {
	if dst.QPN == 0 {
		return errors.New("rdma: destination qpn is zero")
	}
	if dst.LID == 0 && dst.GID == ([16]byte{}) {
		return errors.New("rdma: destination lid and gid are both zero")
	}
	if dst.PSN > maxRDMAStreamPSN {
		return fmt.Errorf("rdma: destination psn %d out of range", dst.PSN)
	}
	var b [rdmaStreamDestinationSize]byte
	b[0] = rdmaStreamHandshakeVersion
	binary.BigEndian.PutUint16(b[1:3], dst.LID)
	binary.BigEndian.PutUint32(b[3:7], dst.QPN)
	binary.BigEndian.PutUint32(b[7:11], dst.PSN)
	b[11] = dst.GIDIndex
	copy(b[12:28], dst.GID[:])
	binary.BigEndian.PutUint32(b[28:32], uint32(dst.ActiveMTU))
	if _, err := w.Write(b[:]); err != nil {
		return fmt.Errorf("rdma: write destination: %w", err)
	}
	return nil
}

func readRDMAStreamDestination(r io.Reader) (rdmaStreamDestination, error) {
	var b [rdmaStreamDestinationSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return rdmaStreamDestination{}, fmt.Errorf("rdma: read destination: %w", err)
	}
	if b[0] != rdmaStreamHandshakeVersion {
		return rdmaStreamDestination{}, errors.New("rdma: destination version mismatch")
	}
	dst := rdmaStreamDestination{
		LID:       binary.BigEndian.Uint16(b[1:3]),
		QPN:       binary.BigEndian.Uint32(b[3:7]),
		PSN:       binary.BigEndian.Uint32(b[7:11]),
		GIDIndex:  b[11],
		ActiveMTU: int32(binary.BigEndian.Uint32(b[28:32])),
	}
	copy(dst.GID[:], b[12:28])
	if dst.QPN == 0 {
		return rdmaStreamDestination{}, errors.New("rdma: destination qpn is zero")
	}
	if dst.LID == 0 && dst.GID == ([16]byte{}) {
		return rdmaStreamDestination{}, errors.New("rdma: destination lid and gid are both zero")
	}
	if dst.PSN > maxRDMAStreamPSN {
		return rdmaStreamDestination{}, fmt.Errorf("rdma: destination psn %d out of range", dst.PSN)
	}
	return dst, nil
}

func writeRDMAStreamFramePayload(w io.Writer, n int) error {
	if n <= 0 {
		return fmt.Errorf("rdma: frame payload %d must be positive", n)
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	if _, err := w.Write(b[:]); err != nil {
		return fmt.Errorf("rdma: write frame payload: %w", err)
	}
	return nil
}

func readRDMAStreamFramePayload(r io.Reader) (int, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("rdma: read frame payload: %w", err)
	}
	n := int(binary.BigEndian.Uint32(b[:]))
	if n <= 0 {
		return 0, fmt.Errorf("rdma: frame payload %d must be positive", n)
	}
	return n, nil
}

func writeRDMAStreamString(w io.Writer, s string) error {
	if len(s) > maxRDMAStreamStringLength {
		return errors.New("rdma: string too long")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(s)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("rdma: write string length: %w", err)
	}
	if _, err := io.WriteString(w, s); err != nil {
		return fmt.Errorf("rdma: write string: %w", err)
	}
	return nil
}

func readRDMAStreamString(r io.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", fmt.Errorf("rdma: read string length: %w", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > maxRDMAStreamStringLength {
		return "", errors.New("rdma: string too long")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("rdma: read string: %w", err)
	}
	return string(buf), nil
}

const (
	rdmaStreamHandshakeVersion = 1
	rdmaStreamDestinationSize  = 32
	maxRDMAStreamPSN           = 0xffffff
	maxRDMAStreamStringLength  = 255
)
