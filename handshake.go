package noisetls

import (
	"crypto/rand"

	"encoding/binary"
	"math"

	"io"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
)

type HandshakeMessages struct {
	Length   uint16
	Messages []*HandshakeMessage
}

type HandshakeMessage struct {
	MessageTypeLen byte
	MessageType    []byte
	MessageLen     uint16
	Message        []byte
}

var dhFuncs = []noise.DHFunc{noise.DH25519}
var ciphers = []noise.CipherFunc{noise.CipherAESGCM, noise.CipherChaChaPoly}
var hashes = []noise.HashFunc{noise.HashSHA256, noise.HashBLAKE2s, noise.HashSHA512, noise.HashBLAKE2b}

func ComposeInitiatorHandshakeMessages(staticKey noise.DHKey, payload []byte) ([]byte, error) {
	totalMsgLen := uint16(0)
	msgBuf := make([]byte, math.MaxUint8+32 /* e */ +len(payload))
	res := make([]byte, 2048)
	res = res[:2]
	written := false
	for _, csp := range cipherSuitePriority {
		cs := cipherSuites[csp]
		state := noise.NewHandshakeState(noise.Config{
			CipherSuite:   cs.cipherSuite,
			Initiator:     true,
			Random:        rand.Reader,
			Pattern:       noise.HandshakeXX,
			Prologue:      prologue,
			StaticKeypair: staticKey,
		})

		msg := msgBuf[:0]
		msg = append(msg, byte(len(cs.name)))
		msg = append(msg, cs.name...)

		lmsg := uint16(len(msg))

		msg = msg[:lmsg+2]

		if !written {
			msg, _, _ = state.WriteMessage(msg, payload)
			written = true
		}

		binary.BigEndian.PutUint16(msg[lmsg:], uint16(len(msg))-lmsg-2)

		lmsg = uint16(len(msg))

		if totalMsgLen+lmsg > math.MaxUint16 {
			return nil, errors.New("Message too big")
		}
		totalMsgLen += lmsg
		res = append(res, msg...)
	}
	binary.BigEndian.PutUint16(res, totalMsgLen)
	return res, nil
}

func ParseHandshake(handshake io.Reader) ([]byte, error) {

	buf := make([]byte, 1024)
	parsedPrologue := make([]byte, 1024)
	parsedPrologue = parsedPrologue[1:2]
	suites := make([]*SuiteSet, 10)
	suites = suites[:0]
	var lastNonEmtyMsg []byte
	for {
		nameSize, csName, err := ReadData1byteLen(handshake, buf) //read ciphersuite name

		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		parsedPrologue = append(parsedPrologue, nameSize)
		parsedPrologue = append(parsedPrologue, csName...)

		strName := string(csName)
		cs, ok := cipherSuites[strName]

		msgSize, csData, err := ReadData2byteLen(handshake, buf)

		if err != nil {
			return nil, err
		}

		if msgSize > 0 {
			lastNonEmtyMsg = csData
		}

		if msgSize == 0 && len(suites) == 0 {
			return nil, errors.New("Zero length initial message is not permitted")
		}

		var foundSuite noise.CipherSuite

		if ok {
			foundSuite = cs.cipherSuite
		}

		suites = append(suites, &SuiteSet{
			cipherSuite: foundSuite,
			message:     lastNonEmtyMsg,
		})

		parsedPrologue[0]++

	}
	return parsedPrologue, nil
}

func ReadData2byteLen(reader io.Reader, buf []byte) (uint16, []byte, error) {
	_, err := reader.Read(buf[:2])
	if err != nil {
		return 0, nil, err
	}
	msgLen := binary.BigEndian.Uint16(buf)

	if len(buf) < int(msgLen) {
		return 0, nil, errors.New("buffer too small")
	}

	read, err := reader.Read(buf[:msgLen])
	if err != nil {
		return 0, nil, err
	}

	return uint16(read), buf[:msgLen], nil
}

func ReadData1byteLen(reader io.Reader, buf []byte) (byte, []byte, error) {
	_, err := reader.Read(buf[:1])
	if err != nil {
		return 0, nil, err
	}
	read, err := reader.Read(buf[:buf[0]])
	if err != nil {
		return 0, nil, err
	}

	return byte(read), buf[:read], nil
}
