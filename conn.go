package noisetls

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
)

type Conn struct {
	conn              net.Conn
	myKeys            noise.DHKey
	PeerKey           []byte
	in, out           halfConn
	handshakeMutex    sync.Mutex
	handshakeComplete bool
	isClient          bool
	handshakeErr      error
	input             *block
	rawInput          *block
	hand              bytes.Buffer // handshake data waiting to be read
}

type halfConn struct {
	sync.Mutex
	cs    *noise.CipherState
	err   error
	bfree *block // list of free blocks

}

func (h *halfConn) Encrypt(block *block) {
	if h.cs != nil {
		block.reserve(len(block.data[2:]) + 16)
		block.data = h.cs.Encrypt(block.data[:2], nil, block.data[2:])
	}
}

// decrypt checks and strips the mac and decrypts the data in b. Returns a
// success boolean

func (h *halfConn) decrypt(b *block) error {
	// pull out payload
	payload := b.data[2:]

	if h.cs != nil {
		payload, err := h.cs.Decrypt(payload[:0], nil, payload)
		if err != nil {
			return err
		}
		b.resize(2 + len(payload))

	}

	return nil
}

func (hc *halfConn) setErrorLocked(err error) error {
	hc.err = err
	return err
}

// newBlock allocates a new block, from hc's free list if possible.
func (hc *halfConn) newBlock() *block {
	b := hc.bfree
	if b == nil {
		return new(block)
	}
	hc.bfree = b.link
	b.link = nil
	b.resize(0)
	return b
}

// freeBlock returns a block to hc's free list.
// The protocol is such that each side only has a block or two on
// its free list at a time, so there's no need to worry about
// trimming the list, etc.
func (hc *halfConn) freeBlock(b *block) {
	b.link = hc.bfree
	hc.bfree = b
}

// splitBlock splits a block after the first n bytes,
// returning a block with those n bytes and a
// block with the remainder.  the latter may be nil.
func (hc *halfConn) splitBlock(b *block, n int) (*block, *block) {
	if len(b.data) <= n {
		return b, nil
	}
	bb := hc.newBlock()
	bb.resize(len(b.data) - n)
	copy(bb.data, b.data[n:])
	b.data = b.data[0:n]
	return b, bb
}

// Access to net.Conn methods.
// Cannot just embed net.Conn because that would
// export the struct field too.

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means Read and Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) Write(b []byte) (int, error) {

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()
	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.handshakeComplete {
		return 0, errors.New("internal error")
	}

	return c.writePacketLocked(b)
}

func (c *Conn) writePacket(data []byte) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	return c.writePacketLocked(data)
}
func (c *Conn) writePacketLocked(data []byte) (int, error) {

	var n int
	for len(data) > 0 {

		m := len(data)

		maxPayloadSize := c.maxPayloadSizeForWrite()
		if m > maxPayloadSize {
			m = maxPayloadSize
		}

		b := c.out.newBlock()
		b.resize(2 + m)
		copy(b.data[2:], data[:m])

		c.out.Encrypt(b)

		binary.BigEndian.PutUint16(b.data, uint16(len(b.data)-2))

		if _, err := c.conn.Write(b.data); err != nil {
			return n, err
		}
		c.out.freeBlock(b)
		n += m
		data = data[m:]
	}

	return n, nil
}

func (c *Conn) maxPayloadSizeForWrite() int {
	return MaxPayloadSize - 16
}

// Read reads data from the connection.
// Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *Conn) Read(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return
	}

	c.in.Lock()
	defer c.in.Unlock()

	if c.input == nil && c.in.err == nil {
		if err := c.readPacket(); err != nil {
			return 0, err
		}
	}

	if err := c.in.err; err != nil {
		return 0, err
	}
	n, err = c.input.Read(b)
	if c.input.off >= len(c.input.data) {
		c.in.freeBlock(c.input)
		c.input = nil
	}
	return n, err
}

// readPacket reads the next noise packet from the connection
// and updates the record layer state.
// c.in.Mutex <= L; c.input == nil.
func (c *Conn) readPacket() error {

	if c.rawInput == nil {
		c.rawInput = c.in.newBlock()
	}
	b := c.rawInput

	// Read header, payload.
	if err := b.readFromUntil(c.conn, 2); err != nil {
		return err
	}

	n := int(binary.BigEndian.Uint16(b.data))

	if err := b.readFromUntil(c.conn, 2+n); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	b, c.rawInput = c.in.splitBlock(b, 2+n)

	err := c.in.decrypt(b)
	if err != nil {
		c.in.setErrorLocked(err)
		return err
	}
	b.off = 2
	c.input = b
	b = nil
	return c.in.err
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// Handshake runs the client or server handshake
// protocol if it has not yet been run.
// Most uses of this package need not call Handshake
// explicitly: the first Read or Write will call it automatically.
func (c *Conn) Handshake() error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	// c.handshakeErr and c.handshakeComplete are protected by
	// c.handshakeMutex. In order to perform a handshake, we need to lock
	// c.in also and c.handshakeMutex must be locked after c.in.
	//
	// However, if a Read() operation is hanging then it'll be holding the
	// lock on c.in and so taking it here would cause all operations that
	// need to check whether a handshake is pending (such as Write) to
	// block.
	//
	// Thus we take c.handshakeMutex first and, if we find that a handshake
	// is needed, then we unlock, acquire c.in and c.handshakeMutex in the
	// correct order, and check again.
	for i := 0; i < 2; i++ {
		if i == 1 {
			c.handshakeMutex.Unlock()
			c.in.Lock()
			defer c.in.Unlock()
			c.handshakeMutex.Lock()
		}

		if err := c.handshakeErr; err != nil {
			return err
		}
		if c.handshakeComplete {
			return nil
		}
	}

	if c.isClient {
		c.handshakeErr = c.RunClientHandshake()
	} else {
		c.handshakeErr = c.RunServerHandshake()
	}
	return c.handshakeErr
}

func (c *Conn) RunClientHandshake() error {

	msg, states, err := ComposeInitiatorHandshakeMessages(c.myKeys, c.PeerKey)

	if err != nil {
		return err
	}

	_, err = c.writePacket(msg)
	if err != nil {
		return err
	}

	if err := c.readPacket(); err != nil {
		return err
	}

	msg = c.input.data[c.input.off:]

	c.in.freeBlock(c.input)
	c.input = nil

	if len(msg) < 1 {
		return errors.New("message length is less than needed")
	}

	if int(msg[0]) > (len(states) - 1) {
		return errors.New("message index out of bounds")
	}

	hs := states[msg[0]]

	_, csIn, csOut, err := hs.ReadMessage(msg, msg[1:])
	if err != nil {
		return err
	}

	for csIn == nil && csOut == nil {
		msg = msg[:0]
		msg, csIn, csOut = hs.WriteMessage(msg, nil)
		_, err = c.writePacket(msg)

		if err != nil {
			return err
		}
		if csIn != nil && csOut != nil {
			break
		}

		if err := c.readPacket(); err != nil {
			return err
		}

		msg := c.input.data[c.input.off:]
		_, csIn, csOut, err = hs.ReadMessage(msg[:0], msg)
		c.in.freeBlock(c.input)
		c.input = nil

		if err != nil {
			return err
		}
	}

	c.in.cs = csIn
	c.out.cs = csOut

	c.handshakeComplete = true
	return nil
}

func (c *Conn) RunServerHandshake() error {

	if err := c.readPacket(); err != nil {
		return err
	}

	msg := c.input.data[c.input.off:]

	hs, index, err := ParseHandshake(c.myKeys, msg)

	c.in.freeBlock(c.input)
	c.input = nil

	if err != nil {
		return err
	}

	msg = msg[0:1]

	msg[0] = index
	msg, csOut, csIn := hs.WriteMessage(msg, nil)
	_, err = c.writePacket(msg)

	if err != nil {
		return err
	}

	for csIn == nil && csOut == nil {

		if err := c.readPacket(); err != nil {
			return err
		}

		msg := c.input.data[c.input.off:]
		_, csOut, csIn, err = hs.ReadMessage(msg[:0], msg)
		c.in.freeBlock(c.input)
		c.input = nil

		if err != nil {
			return err
		}

		if csIn != nil && csOut != nil {
			break
		}

		msg = msg[:0]
		msg, csOut, csIn = hs.WriteMessage(msg, nil)
		_, err = c.writePacket(msg)

		if err != nil {
			return err
		}

	}

	c.in.cs = csIn
	c.out.cs = csOut
	c.handshakeComplete = true
	return nil
}
