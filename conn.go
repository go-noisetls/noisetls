package noisetls

import (
	"net"
	"time"
	"sync"
	"github.com/flynn/noise"
	"crypto/rand"
	"github.com/pkg/errors"
	"encoding/binary"
	"io"
	"bytes"
)


type Conn struct {
	conn              net.Conn
	cs                noise.CipherSuite
	hs                *noise.HandshakeState
	myKeys            noise.DHKey
	PeerKey           []byte
	in, out           halfConn
	handshakeMutex    sync.Mutex
	handshakeComplete bool
	isClient          bool
	handshakeErr      error
	input *block
	rawInput *block
	hand      bytes.Buffer // handshake data waiting to be read
}

type halfConn struct {
	sync.Mutex
	cs *noise.CipherState
	err error
	bfree          *block   // list of free blocks

}

func (h *halfConn) Encrypt(data []byte) []byte {
	if h.cs != nil{
		return h.cs.Encrypt(nil,nil,data)
	}
	return data
}


// decrypt checks and strips the mac and decrypts the data in b. Returns a
// success boolean, the number of bytes to skip from the start of the record in
// order to get the application payload, and an optional alert value.
func (h *halfConn) decrypt(b *block) (error) {
	// pull out payload
	payload := b.data[PacketHeaderLen:]

	if h.cs != nil{
		payload, err :=  h.cs.Decrypt(payload[:0],nil,payload)
		if err != nil{
			return err
		}
		b.resize(PacketHeaderLen + len(payload))

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


	return c.writePacketLocked(PacketTypeData, b)
}


func (c *Conn) writePacket(typ uint16, data []byte) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	return c.writePacketLocked(typ, data)
}
func (c *Conn) writePacketLocked(typ uint16, data []byte) (int, error) {

	var n int
	for len(data) > 0 {

		m := len(data)

		maxPayloadSize := c.maxPayloadSizeForWrite(typ)
		if m > maxPayloadSize{
			m = maxPayloadSize
		}

		payload := c.out.Encrypt(data[:m])
		packet := &Packet{
			Version:1,
			Type:typ,
			Payload:payload,
		}
		serialized, err := packet.Marshal()
		if err != nil{
			return 0, err
		}

		if _, err := c.conn.Write(serialized); err != nil{
			return n, err
		}
		n += m
		data = data[m:]
	}

	return n, nil
}

func (c *Conn) maxPayloadSizeForWrite(typ uint16) int {
	return MaxPayloadSize - 16
}

// Read reads data from the connection.
// Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func(c *Conn) Read(b []byte) (n int, err error) {
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
		if err := c.readPacket(PacketTypeData); err != nil {
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


// readRecord reads the next TLS record from the connection
// and updates the record layer state.
// c.in.Mutex <= L; c.input == nil.
func (c *Conn) readPacket(packetType uint16) error {
	switch packetType {
	default:
		return c.in.setErrorLocked(errors.New("tls: unknown record type requested"))
	case PacketTypeHandshake:
		if c.handshakeComplete {
			return c.in.setErrorLocked(errors.New("tls: handshake or ChangeCipherSpec requested while not in handshake"))
		}
	case PacketTypeData:
		if !c.handshakeComplete {
			return c.in.setErrorLocked(errors.New("tls: application data record requested while in handshake"))
		}
	}

	if c.rawInput == nil {
		c.rawInput = c.in.newBlock()
	}
	b := c.rawInput

	// Read header, payload.
	if err := b.readFromUntil(c.conn, PacketHeaderLen); err != nil {
		return err
	}

	ver := binary.BigEndian.Uint16(b.data)
	if ver != 1{

	}
	typ := binary.BigEndian.Uint16(b.data[2:])
	n := int(binary.BigEndian.Uint16(b.data[4:]))


	if err := b.readFromUntil(c.conn, PacketHeaderLen+n); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	b, c.rawInput = c.in.splitBlock(b, PacketHeaderLen+n)
	// Process message.
	err := c.in.decrypt(b)
	if err != nil {
		c.in.setErrorLocked(err)
		return err
	}
	b.off = PacketHeaderLen
	data := b.data[b.off:]

	switch typ {
	default:
		return c.in.setErrorLocked(errors.New("unexpected packet type"))

	case PacketTypeData:
		if typ != packetType {
			return c.in.setErrorLocked(errors.New("unexpected packet type"))
		}
		c.input = b
		b = nil
	case PacketTypeHandshake:
		if typ != packetType {
			return c.in.setErrorLocked(errors.New("unexpected packet type"))
		}
		c.hand.Write(data)
	}

	if b != nil {
		c.in.freeBlock(b)
	}
	return c.in.err
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func(c *Conn) Close() error{
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



	if c.isClient{
		c.handshakeErr = c.RunClientHandshake()
	} else {
		c.handshakeErr = c.RunServerHandshake()
	}
	return c.handshakeErr
}

func (c *Conn) RunClientHandshake() error {


	c.InitHandshakeState(true, c.PeerKey)
	buf := make([]byte, 1024*2)
	msg, _, _ := c.hs.WriteMessage(buf[:0], nil)
	_, err := c.writePacket(PacketTypeHandshake, msg)
	if err != nil{
		return err
	}

	if err := c.in.err; err != nil {
		return  err
	}
	if err := c.readPacket(PacketTypeHandshake); err != nil {
		return err
	}

	msg = c.hand.Next(c.hand.Len())
	_, csOut, csIn, err := c.hs.ReadMessage(buf[:0], msg)
	if err != nil{
		return err
	}
	c.out.cs = csOut
	c.in.cs = csIn
	c.handshakeComplete = true
	return nil
}

func (c *Conn) RunServerHandshake() error {

	c.InitHandshakeState(false, nil)
	buf := make([]byte, 1024*2)

	if err := c.readPacket(PacketTypeHandshake); err != nil {
		return err
	}

	msg := c.hand.Next(c.hand.Len())
	_, _, _, err := c.hs.ReadMessage(buf[:0], msg)

	if err != nil{
		return err
	}
	msg, csIn, csOut := c.hs.WriteMessage(buf[:0], nil)
	_, err = c.writePacket(PacketTypeHandshake, msg)

	if err != nil{
		return err
	}
	c.out.cs = csOut
	c.in.cs = csIn
	c.handshakeComplete = true
	return nil
}

func (c *Conn) InitHandshakeState(initiator bool, peerStatic []byte) {
	c.hs = noise.NewHandshakeState(noise.Config{CipherSuite: c.cs, Random: rand.Reader, Pattern: noise.HandshakeIK, Initiator: initiator, Prologue: []byte("ABC"), StaticKeypair: c.myKeys, PeerStatic: peerStatic})
}