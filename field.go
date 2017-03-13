package noisetls

import (
	"encoding/binary"
	"errors"
)

const (
	MessageTypePadding uint16 = iota
	MessageTypeData
	MessageTypeCustomCert = 1024
)

type field struct {
	Type uint16
	Data []byte
}

func ParseMessages(payload []byte) ([]*field, error) {

	if len(payload) < msgHeaderSize {
		return nil, errors.New("payload too small")
	}

	msgs := make([]*field, 0, 1)

	off := uint16(0)
	for {
		msgLen := binary.BigEndian.Uint16(payload[off:])
		if int(off+msgLen) > len(payload) {
			return nil, errors.New("invalid size")
		}

		off += 2
		msgType := binary.BigEndian.Uint16(payload[off:])
		off += 2
		msgs = append(msgs, &field{
			Type: msgType,
			Data: payload[off : off+msgLen-uint16Size],
		})
		off += msgLen - uint16Size
		if int(off) >= (len(payload) - msgHeaderSize) {
			break
		}
	}
	return msgs, nil
}
