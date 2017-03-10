package noisetls

import (
	"encoding/binary"
	"math"

	"crypto/rand"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
)

type HandshakeMessage struct {
	Config  *HandshakeConfig
	Message []byte
}

func ComposeInitiatorHandshakeMessages(s noise.DHKey, rs []byte, payload []byte) ([]byte, []*noise.HandshakeState, error) {

	if len(rs) != 0 && len(rs) != noise.DH25519.DHLen() {
		return nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}
	res := make([]byte, 0, 2048)

	usedPatterns := []noise.HandshakePattern{noise.HandshakeXX}

	prologue := make([]byte, 1, 1024)

	//we checked this in init
	prologue[0] = byte(len(protoCipherPriorities[noise.HandshakeXX.Name]))

	prologue = append(prologue, prologues[noise.HandshakeXX.Name]...)

	//add IK if remote static is provided
	if len(rs) > 0 {
		usedPatterns = append(usedPatterns, noise.HandshakeIK)
		prologue = append(prologue, prologues[noise.HandshakeIK.Name]...)

		if len(protoCipherPriorities[noise.HandshakeIK.Name])+int(prologue[0]) > math.MaxUint8 {
			return nil, nil, errors.New("too many sub-messages for a single message")
		}

		prologue[0] += byte(len(protoCipherPriorities[noise.HandshakeIK.Name]))
	}

	states := make([]*noise.HandshakeState, 0, prologue[0])

	for _, pattern := range usedPatterns {

		for _, csp := range protoCipherPriorities[pattern.Name] {
			cfg := handshakeConfigs[csp]

			msg := res[len(res):] //append to res

			//append message type : 1 byte len + len bytes type name

			msg = append(msg, cfg.NameLength)
			msg = append(msg, cfg.Name...)

			res = append(res, msg...)

			//reset position
			msg = msg[len(msg):]

			//append cipher suite contents : 2 byte len + len bytes message.

			msg = append(msg, 0, 0) // add 2 bytes for length

			rs := rs
			if !cfg.UseRemoteStatic {
				rs = nil
			}
			state := noise.NewHandshakeState(noise.Config{
				StaticKeypair: s,
				Initiator:     true,
				Pattern:       cfg.Pattern,
				CipherSuite:   noise.NewCipherSuite(cfg.DH, cfg.Cipher, cfg.Hash),
				PeerStatic:    rs,
				Prologue:      prologue,
				Random:        rand.Reader,
			})

			if CanWrite(cfg.Pattern, 0) {
				msg, _, _ = state.WriteMessage(msg, payload)
			} else {
				msg, _, _ = state.WriteMessage(msg, nil)
			}

			binary.BigEndian.PutUint16(msg, uint16(len(msg)-uint16Size)) //write calculated length at the beginning

			states = append(states, state)

			// we cannot send the message if its length exceeds 2^16 - 1
			if len(res)+len(msg) > (math.MaxUint16 - uint16Size) {
				return nil, nil, errors.New("Message is too big")
			}
			res = append(res, msg...)

		}
	}
	return res, states, nil
}

func CanWrite(pattern noise.HandshakePattern, msgIndex int) bool {
	for _, m := range pattern.Messages[msgIndex] {
		if m == noise.MessagePatternS {
			return true
		}
	}
	return false
}

func ParseHandshake(s noise.DHKey, handshake []byte) (payload []byte, hs *noise.HandshakeState, messageIndex byte, err error) {

	parsedPrologue := make([]byte, 1, 1024)
	messages := make([]*HandshakeMessage, 0, 16)
	for {
		if len(handshake) == 0 {
			break
		}

		var typeName, msg []byte
		handshake, typeName, err = readData(handshake, 1) //read protocol name

		if err != nil {
			return nil, nil, 0, err
		}

		parsedPrologue = append(parsedPrologue, byte(len(typeName)))
		parsedPrologue = append(parsedPrologue, typeName...)

		handshake, msg, err = readData(handshake, 2) //read handshake data

		if err != nil {
			return nil, nil, 0, err
		}

		//lookup protocol config

		nameKey := hashKey(typeName)
		cfg, ok := handshakeConfigs[nameKey]
		if ok {

			messages = append(messages, &HandshakeMessage{
				Config:  cfg,
				Message: msg,
			})
		}

		if parsedPrologue[0] == math.MaxUint8 {
			return nil, nil, 0, errors.New("too many messages")
		}

		parsedPrologue[0]++

	}

	//choose protocol that we want to use, according to server priorities

	for _, pr := range protoPriorities {
		for _, p := range protoCipherPriorities[pr] {
			for i, m := range messages {
				if p == m.Config.NameKey {
					state := noise.NewHandshakeState(noise.Config{
						StaticKeypair: s,
						Initiator:     false,
						Pattern:       m.Config.Pattern,
						CipherSuite:   noise.NewCipherSuite(m.Config.DH, m.Config.Cipher, m.Config.Hash),
						Prologue:      parsedPrologue,
						Random:        rand.Reader,
					})

					payload, _, _, err := state.ReadMessage(nil, m.Message)
					if err != nil {
						return nil, nil, 0, err
					}

					return payload, state, byte(i), nil
				}
			}

		}
	}

	return nil, nil, 0, errors.New("no supported protocols found")
}

func readData(data []byte, sizeBytes int) (rest []byte, msg []byte, err error) {
	if sizeBytes != 1 && sizeBytes != 2 {
		return nil, nil, errors.New("only 1 and 2 byte lengths are supported")
	}

	if len(data) < sizeBytes {
		return nil, nil, errors.New("buffer too small")
	}

	msgLen := 0

	switch sizeBytes {
	case 1:
		msgLen = int(data[0])
		break
	case 2:
		msgLen = int(binary.BigEndian.Uint16(data))
		break

	}

	if msgLen == 0 {
		return nil, nil, errors.New("zero length messages are not supported")
	}

	if len(data) < (msgLen + sizeBytes) {
		return nil, nil, errors.New("invalid length")
	}

	rest = data[(msgLen + sizeBytes):]
	msg = data[sizeBytes:(msgLen + sizeBytes)]

	return rest, msg, nil
}
