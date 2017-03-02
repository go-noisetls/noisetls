package noisetls

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"math"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
)

const MaxPayloadSize = math.MaxUint16

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
	padding           uint16
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
		if m > int(maxPayloadSize) {
			m = int(maxPayloadSize)
		}

		b := c.out.encryptIfNeeded(data[:m])

		if _, err := c.conn.Write(b.data); err != nil {
			return n, err
		}
		c.out.freeBlock(b)
		n += m
		data = data[m:]
	}

	return n, nil
}

func (c *Conn) maxPayloadSizeForWrite() uint16 {
	return MaxPayloadSize - uint8Size - 16
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
	if err := b.readFromUntil(c.conn, uint8Size); err != nil {
		return err
	}

	n := int(binary.BigEndian.Uint16(b.data))

	if err := b.readFromUntil(c.conn, uint8Size+n); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	b, c.rawInput = c.in.splitBlock(b, uint8Size+n)

	err := c.in.decryptIfNeeded(b)
	if err != nil {
		c.in.setErrorLocked(err)
		return err
	}

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
	c.in.padding, c.out.padding = c.padding, c.padding
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
	c.in.padding, c.out.padding = c.padding, c.padding
	c.handshakeComplete = true
	return nil
}
