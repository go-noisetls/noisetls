package noisetls

import (
	"testing"
	"github.com/flynn/noise"
	"bytes"
	"github.com/stretchr/testify/assert"
	"encoding/binary"
)

func TestHandshake(t *testing.T){
	hm, _ := ComposeInitiatorHandshakeMessages(noise.DHKey{}, nil)

	size := binary.BigEndian.Uint16(hm)

	assert.Equal(t, size, uint16(len(hm[2:])))
	parsedPrologue,err := ParseHandshake(bytes.NewBuffer(hm[2:]))
	assert.NoError(t, err)
	assert.Equal(t, parsedPrologue, prologue)
}
