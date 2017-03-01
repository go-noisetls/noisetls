package noisetls

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

type Packet []byte

const MaxPayloadSize = 2<<16 - 1

func (p Packet) Marshal(buf []byte) ([]byte, error) {
	if len(p) > MaxPayloadSize {
		return nil, errors.New("Payload size exceeds 65kb")
	}

	res := append(buf, 0, 0)
	binary.BigEndian.PutUint16(res, uint16(len(p)))
	res = append(res, p...)
	return res, nil
}
