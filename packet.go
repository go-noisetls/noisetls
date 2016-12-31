package noisetls

import (
	"encoding/binary"
	"github.com/pkg/errors"
)

const (
	PacketTypeHandshake uint16 = 4
	PacketTypeData uint16 = 10
	PacketHeaderLen = 8
)


type Packet struct {
	Version uint16
	Type uint16
	Payload []byte
}

const MaxPayloadSize = 16*1024

func (p *Packet) Marshal()([]byte, error ){
	if len(p.Payload) > MaxPayloadSize{
		return nil, errors.New("Payload size exceeds 16kb")
	}
	res := make([]byte, len(p.Payload) + PacketHeaderLen)
	binary.BigEndian.PutUint16(res, p.Version)
	binary.BigEndian.PutUint16(res[2:], p.Type)
	binary.BigEndian.PutUint16(res[4:], uint16(len(p.Payload)))
	binary.BigEndian.PutUint16(res[6:], 0) //reserved
	copy(res[PacketHeaderLen:], p.Payload)
	return res, nil
}