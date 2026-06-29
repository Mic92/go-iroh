package blobs

import (
	"fmt"

	"github.com/tmc/go-iroh/endpointticket"
)

// ALPN is the application protocol name for Rust iroh-blobs.
const ALPN = "/iroh-bytes/4"

// RequestType identifies an iroh-blobs request variant.
type RequestType uint64

const (
	RequestGet RequestType = iota
	RequestObserve
	RequestSlot2
	RequestSlot3
	RequestSlot4
	RequestSlot5
	RequestSlot6
	RequestSlot7
	RequestPush
	RequestGetMany
)

// GetRequest requests a blob or hash sequence from a provider.
type GetRequest struct {
	Hash   Hash
	Ranges ChunkRangesSeq
}

// NewGetRequest returns a get request for hash and ranges.
func NewGetRequest(hash Hash, ranges ChunkRangesSeq) GetRequest {
	return GetRequest{Hash: hash, Ranges: ranges}
}

// GetBlob returns a request for a single raw blob.
func GetBlob(hash Hash) GetRequest {
	return NewGetRequest(hash, ChunkRangesSeqFromRanges([]ChunkRanges{RangeAll()}))
}

// GetAll returns a request for a hash sequence and all its children.
func GetAll(hash Hash) GetRequest {
	return NewGetRequest(hash, ChunkRangesSeqAll())
}

// GetBlobRanges returns a request for selected ranges from a single raw blob.
func GetBlobRanges(hash Hash, ranges ChunkRanges) GetRequest {
	return NewGetRequest(hash, ChunkRangesSeqFromRanges([]ChunkRanges{ranges}))
}

// Content returns the hash and inferred format requested by r.
func (r GetRequest) Content() HashAndFormat {
	if r.Ranges.IsBlob() {
		return RawHash(r.Hash)
	}
	return HashSeqHash(r.Hash)
}

func (r GetRequest) encode(b []byte) []byte {
	b = append(b, r.Hash[:]...)
	return r.Ranges.encode(b)
}

func decodeGetRequest(p *parser) (GetRequest, error) {
	hashBytes, err := p.bytes(HashSize)
	if err != nil {
		return GetRequest{}, wrapDecodeErr(err)
	}
	var hash Hash
	copy(hash[:], hashBytes)
	ranges, err := decodeChunkRangesSeq(p)
	if err != nil {
		return GetRequest{}, err
	}
	return GetRequest{Hash: hash, Ranges: ranges}, nil
}

// GetManyRequest requests multiple raw blobs from one provider.
type GetManyRequest struct {
	Hashes []Hash
	Ranges ChunkRangesSeq
}

// NewGetManyRequest returns a request for hashes and ranges.
func NewGetManyRequest(hashes []Hash, ranges ChunkRangesSeq) GetManyRequest {
	return GetManyRequest{Hashes: append([]Hash(nil), hashes...), Ranges: ranges}
}

func (r GetManyRequest) encode(b []byte) []byte {
	b = appendVarint(b, uint64(len(r.Hashes)))
	for _, h := range r.Hashes {
		b = append(b, h[:]...)
	}
	return r.Ranges.encode(b)
}

func decodeGetManyRequest(p *parser) (GetManyRequest, error) {
	n, err := p.varint()
	if err != nil {
		return GetManyRequest{}, wrapDecodeErr(err)
	}
	hashes := make([]Hash, 0, n)
	for range n {
		hashBytes, err := p.bytes(HashSize)
		if err != nil {
			return GetManyRequest{}, wrapDecodeErr(err)
		}
		var hash Hash
		copy(hash[:], hashBytes)
		hashes = append(hashes, hash)
	}
	ranges, err := decodeChunkRangesSeq(p)
	if err != nil {
		return GetManyRequest{}, err
	}
	return GetManyRequest{Hashes: hashes, Ranges: ranges}, nil
}

// Request is an iroh-blobs provider request.
type Request struct {
	Type    RequestType
	Get     *GetRequest
	GetMany *GetManyRequest
}

// EncodeRequestBytes encodes req as Rust-compatible postcard bytes.
func EncodeRequestBytes(req Request) ([]byte, error) {
	var b []byte
	switch req.Type {
	case RequestGet:
		if req.Get == nil {
			return nil, fmt.Errorf("blob request: missing get request")
		}
		b = appendVarint(b, uint64(RequestGet))
		b = req.Get.encode(b)
	case RequestGetMany:
		if req.GetMany == nil {
			return nil, fmt.Errorf("blob request: missing get-many request")
		}
		b = appendVarint(b, uint64(RequestGetMany))
		b = req.GetMany.encode(b)
	default:
		return nil, fmt.Errorf("blob request: unsupported request type %d", req.Type)
	}
	return b, nil
}

// DecodeRequestBytes decodes Rust-compatible postcard request bytes.
func DecodeRequestBytes(b []byte) (Request, error) {
	var req Request
	err := decodeToEnd(b, func(p *parser) error {
		t, err := p.varint()
		if err != nil {
			return wrapDecodeErr(err)
		}
		switch RequestType(t) {
		case RequestGet:
			get, err := decodeGetRequest(p)
			if err != nil {
				return err
			}
			req = Request{Type: RequestGet, Get: &get}
		case RequestGetMany:
			getMany, err := decodeGetManyRequest(p)
			if err != nil {
				return err
			}
			req = Request{Type: RequestGetMany, GetMany: &getMany}
		default:
			return &endpointticket.ParseError{
				Kind:    endpointticket.ParseErrorKindVerify,
				Message: fmt.Sprintf("unsupported request type %d", t),
			}
		}
		return nil
	})
	return req, err
}

// EncodeGetRequestBytes encodes r as a full Request::Get message.
func EncodeGetRequestBytes(r GetRequest) []byte {
	var b []byte
	b = appendVarint(b, uint64(RequestGet))
	b = r.encode(b)
	return b
}

// DecodeGetRequestBytes decodes a full Request::Get message.
func DecodeGetRequestBytes(b []byte) (GetRequest, error) {
	req, err := DecodeRequestBytes(b)
	if err != nil {
		return GetRequest{}, err
	}
	if req.Type != RequestGet || req.Get == nil {
		return GetRequest{}, &endpointticket.ParseError{
			Kind:    endpointticket.ParseErrorKindVerify,
			Message: "not a get request",
		}
	}
	return *req.Get, nil
}
