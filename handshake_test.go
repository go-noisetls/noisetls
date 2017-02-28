package noisetls

import (
	"encoding/binary"
	"testing"

	"github.com/flynn/noise"

	"crypto/rand"

	"github.com/stretchr/testify/assert"
)

func TestHandshake(t *testing.T) {

	ki := noise.DH25519.GenerateKeypair(rand.Reader)
	ks := noise.DH25519.GenerateKeypair(rand.Reader)

	hm, istates, err := ComposeInitiatorHandshakeMessages(ki, ks.Public)
	assert.NoError(t, err)

	size := binary.BigEndian.Uint16(hm)
	assert.Equal(t, size, uint16(len(hm[2:])))

	rstates, err := ParseHandshake(ks, hm[2:])
	assert.NoError(t, err)

	for i, rs := range rstates {
		msg, _, _ := rs.WriteMessage(nil, nil)
		_, _, _, err := istates[i].ReadMessage(nil, msg)
		assert.NoError(t, err)
	}

}
