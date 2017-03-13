package noisetls

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"math"

	"fmt"

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
	payload           []byte
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

//InitializePacket adds additional sub-messages if needed
func (c *Conn) InitializePacket() *block {
	block := c.out.newBlock()
	block.resize(uint16Size)
	return block
}

func (c *Conn) writePacketLocked(data []byte) (int, error) {

	var n int
	for len(data) > 0 {

		m := len(data)

		packet := c.InitializePacket()

		maxPayloadSize := c.maxPayloadSizeForWrite(packet)
		if m > int(maxPayloadSize) {
			m = int(maxPayloadSize)
		}

		if c.out.cs != nil {
			packet.AddField(data[:m], MessageTypeData)
		} else {
			packet.resize(len(packet.data) + len(data))
			copy(packet.data[uint16Size:len(packet.data)], data[:m])
			binary.BigEndian.PutUint16(packet.data, uint16(len(data)))
		}

		if c.out.cs != nil && c.padding == 0 {
			packet.AddPadding(c.padding)
		}

		b := c.out.encryptIfNeeded(packet)
		c.out.freeBlock(packet)

		if _, err := c.conn.Write(b); err != nil {
			return n, err
		}
		n += m
		data = data[m:]
	}

	return n, nil
}

func (c *Conn) maxPayloadSizeForWrite(block *block) uint16 {
	res := MaxPayloadSize - uint16(len(block.data))
	if c.out.cs != nil {
		if c.padding > 0 {
			return res - macSize - msgHeaderSize*2
		} else {
			return res - macSize - msgHeaderSize
		}
	}
	return res

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
	if err := b.readFromUntil(c.conn, uint16Size); err != nil {
		return err
	}

	n := int(binary.BigEndian.Uint16(b.data))

	if err := b.readFromUntil(c.conn, uint16Size+n); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	b, c.rawInput = c.in.splitBlock(b, uint16Size+n)
	defer c.in.freeBlock(b)

	payload, err := c.in.decryptIfNeeded(b)
	if err != nil {
		c.in.setErrorLocked(err)
		return err
	}

	in := c.in.newBlock()
	if c.in.cs != nil {
		messages, err := ParseMessages(payload)

		if err != nil {
			c.in.setErrorLocked(err)
			return err
		}

		msg := messages[0]

		in.resize(len(msg.Data))
		copy(in.data, msg.Data)
	} else {
		in.resize(len(payload))
		copy(in.data, payload)
	}

	c.input = in
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

	var (
		msg, payload []byte
		states       []*noise.HandshakeState
		err          error
		csIn, csOut  *noise.CipherState
	)

	b := c.out.newBlock()

	b.AddField(c.payload, MessageTypeCustomCert)

	if msg, states, err = ComposeInitiatorHandshakeMessages(c.myKeys, c.PeerKey, b.data); err != nil {
		return err
	}

	c.out.freeBlock(b)

	if _, err = c.writePacket(msg); err != nil {
		return err
	}

	if err := c.readPacket(); err != nil {
		return err
	}

	msg = c.input.data[c.input.off:]

	c.in.freeBlock(c.input)
	c.input = nil

	if len(msg) < macSize {
		return errors.New("message is too small")
	}

	if int(msg[0]) > (len(states) - 1) {
		return errors.New("message index out of bounds")
	}

	hs := states[msg[0]]
	mType := msg[1]

	if mType != 0 {
		return errors.New("Only pure IK is supported")
	}

	if payload, csIn, csOut, err = hs.ReadMessage(msg[:0], msg[2:]); err != nil {
		return err
	}

	if err = processPayload(payload); err != nil {
		return err
	}

	for csIn == nil && csOut == nil {
		msg = msg[:0]
		if len(c.PeerKey) == 0 {
			msg, csIn, csOut = hs.WriteMessage(msg, payload)
		} else {
			msg, csIn, csOut = hs.WriteMessage(msg, nil)
		}

		if _, err = c.writePacket(msg); err != nil {
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

	payload, hs, index, err := ParseHandshake(c.myKeys, msg)

	c.in.freeBlock(c.input)
	c.input = nil

	if err != nil {
		return err
	}

	err = processPayload(payload)
	if err != nil {
		return err
	}

	msg = msg[0:2]

	msg[0] = index
	msg[1] = 0 // xx_fallback is not supported yet

	//server can safely answer with payload as both XX and IK encrypt it

	b := c.out.newBlock()

	b.AddField(c.payload, MessageTypeCustomCert)

	msg, csOut, csIn := hs.WriteMessage(msg, b.data)
	_, err = c.writePacket(msg)
	c.out.freeBlock(b)

	if err != nil {
		return err
	}

	for csIn == nil && csOut == nil {

		if err := c.readPacket(); err != nil {
			return err
		}

		msg := c.input.data[c.input.off:]
		payload, csOut, csIn, err = hs.ReadMessage(msg[:0], msg)

		c.in.freeBlock(c.input)
		c.input = nil

		if err != nil {
			return err
		}

		processPayload(payload)

		if csIn != nil && csOut != nil {
			break
		}

		msg = msg[:0]
		msg, csOut, csIn = hs.WriteMessage(msg, c.payload)
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

func processPayload(payload []byte) error {
	if len(payload) > 0 {
		msgs, err := ParseMessages(payload)

		if err != nil {
			return err
		}

		for _, m := range msgs {
			fmt.Println(m.Type)
		}
	}
	return nil
}
