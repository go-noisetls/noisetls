package noisetls

import "encoding/binary"

const (
	MessageTypePadding uint16 = iota
	MessageTypeData
)

type TransportMessage struct {
	Type uint16
	Data []byte
}

func (t *TransportMessage) Size() int {
	return uint16Size + uint16Size + len(t.Data) // size + type + data
}

func (t *TransportMessage) Marshal(out []byte) []byte {
	out = append(out, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(out[len(out)-4:], uint16(len(t.Data)+uint16Size))
	binary.BigEndian.PutUint16(out[len(out)-2:], t.Type)
	return append(out, t.Data...)
}
