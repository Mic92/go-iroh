package postcard

import internalpostcard "github.com/tmc/go-iroh/internal/postcard"

type (
	Encoder     = internalpostcard.Encoder
	Decoder     = internalpostcard.Decoder
	Marshaler   = internalpostcard.Marshaler
	EncoderTo   = internalpostcard.EncoderTo
	DecoderFrom = internalpostcard.DecoderFrom
)

// Marshal encodes v in postcard format.
func Marshal(v any) ([]byte, error) { return internalpostcard.Marshal(v) }

// Unmarshal decodes postcard data into v.
func Unmarshal(data []byte, v any) error { return internalpostcard.Unmarshal(data, v) }

// NewDecoder returns a decoder reading b.
func NewDecoder(b []byte) *Decoder { return internalpostcard.NewDecoder(b) }
