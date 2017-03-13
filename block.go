package noisetls

import (
	"encoding/binary"
	"io"
	"math"
)

// A block is a simple data buffer.
type block struct {
	data []byte
	off  int // index for Read
	link *block
}

// resize resizes block to be n bytes, growing if necessary.
func (b *block) resize(n int) {
	if n > cap(b.data) {
		b.reserve(n)
	}
	b.data = b.data[0:n]
}

// reserve makes sure that block contains a capacity of at least n bytes.
func (b *block) reserve(n int) {
	if cap(b.data) >= n {
		return
	}
	m := cap(b.data)
	if m == 0 {
		m = 1024
	}
	for m < n {
		m *= 2
	}
	data := make([]byte, len(b.data), m)
	copy(data, b.data)
	b.data = data
}

// readFromUntil reads from r into b until b contains at least n bytes
// or else returns an error.
func (b *block) readFromUntil(r io.Reader, n int) error {
	// quick case
	if len(b.data) >= n {
		return nil
	}

	// read until have enough.
	b.reserve(n)
	for {
		m, err := r.Read(b.data[len(b.data):cap(b.data)])
		if err != nil {
			return err
		}
		b.data = b.data[0 : len(b.data)+m]
		if len(b.data) >= n {
			break
		}

	}
	return nil
}

func (b *block) Read(p []byte) (n int, err error) {
	n = copy(p, b.data[b.off:])
	b.off += n
	return
}

func (b *block) AddPadding(padding uint16) {

	payloadSize := -uint16Size + len(b.data) + msgHeaderSize /*zero padding*/ + macSize

	if payloadSize > MaxPayloadSize {
		panic("no space left for padding")
	}

	paddingSize := padding - uint16(payloadSize)%padding

	beforePadding := len(b.data)

	b.resize(beforePadding + msgHeaderSize + int(paddingSize))
	binary.BigEndian.PutUint16(b.data[beforePadding:], uint16(paddingSize+uint16Size))
	binary.BigEndian.PutUint16(b.data[beforePadding+2:], MessageTypePadding)
}

func (b *block) AddField(data []byte, msgType uint16) {

	b.reserve(len(b.data) + len(data) + msgHeaderSize)
	b.data = append(b.data, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(b.data[len(b.data)-4:], uint16(len(data)+uint16Size))
	binary.BigEndian.PutUint16(b.data[len(b.data)-2:], msgType)
	b.data = append(b.data, data...)

	if len(b.data) > math.MaxUint16 {
		panic("block is too big")
	}
}
