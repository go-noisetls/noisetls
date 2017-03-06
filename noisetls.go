package noisetls

import (
	"net"

	"github.com/flynn/noise"
)

// Server returns a new TLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Server(conn net.Conn, key noise.DHKey, payload []byte) *Conn {
	return &Conn{
		conn:    conn,
		myKeys:  key,
		padding: 128,
		payload: payload,
	}
}

// Client returns a new TLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn net.Conn, key noise.DHKey, serverKey []byte, payload []byte) *Conn {
	return &Conn{
		conn:     conn,
		myKeys:   key,
		PeerKey:  serverKey,
		isClient: true,
		padding:  128,
		payload:  payload,
	}
}

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	key     noise.DHKey
	payload []byte
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.key, l.payload), nil
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with Server.
func NewListener(inner net.Listener, key noise.DHKey, payload []byte) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.key = key
	l.payload = payload
	return l
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
func Listen(network, laddr string, key noise.DHKey, payload []byte) (net.Listener, error) {

	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, key, payload), nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a TLS handshake, returning the resulting TLS connection. Any
// timeout or deadline given in the dialer apply to connection and TLS
// handshake as a whole.
//
// DialWithDialer interprets a nil configuration as equivalent to the zero
// configuration; see the documentation of Config for the defaults.
func DialWithDialer(dialer *net.Dialer, network, addr string, key noise.DHKey, serverKey []byte, payload []byte) (*Conn, error) {

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	conn := Client(rawConn, key, serverKey, payload)

	return conn, nil
}

func Dial(network, addr string, key noise.DHKey, serverKey []byte, payload []byte) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, key, serverKey, payload)
}
