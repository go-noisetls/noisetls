package noisetls

import (
	"encoding/binary"
	"io"
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

// PrepareStructure takes padding size, length of data to be transmitted and creates the following packet structure:
// [packet size] | [padding size] | padding | data | MAC
// everything will be encrypted except for the packet size
// If padding is used, then packet size is either a multiple of paddingSize or MaxPayloadSize
// Returns slice to encrypt
func (b *block) PrepareStructure(paddingSize int, data []byte, overhead int) []byte {
	payloadSize := uint16Size + len(data) + overhead // 2 bytes padding size, data itself, MAC

	if paddingSize > 0 {
		paddingSize -= payloadSize % paddingSize
		if payloadSize+paddingSize > MaxPayloadSize {
			paddingSize = MaxPayloadSize - payloadSize
		}
	}

	packetSize := uint16Size + paddingSize + payloadSize // 2 bytes block size, 2 bytes padding size, padding itself, app data itself, MAC

	b.resize(packetSize)
	dataOffset := uint16Size + uint16Size + paddingSize

	b.off = dataOffset
	copy(b.data[b.off:], data)

	binary.BigEndian.PutUint16(b.data, uint16(packetSize-uint16Size))    //write total packet size
	binary.BigEndian.PutUint16(b.data[uint16Size:], uint16(paddingSize)) // write padding size
	return b.data[uint16Size: packetSize-overhead]
}
