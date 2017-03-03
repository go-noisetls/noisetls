package noisetls

import (
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

	rstate, index, err := ParseHandshake(ks, hm)
	assert.NoError(t, err)

	msg := make([]byte, 10*1024)
	rand.Read(msg)
	buf := make([]byte, 10*1024+16)

	//at this stage server and client have already exchanged their first message
	sender := rstate
	receiver := istates[index]

	//keep sending messages until we get cipherstates or error
	for err == nil {

		var cs1i, cs2i, cs1r, cs2r *noise.CipherState

		msg, cs1r, cs2r = sender.WriteMessage(buf[:0], nil)
		_, cs1i, cs2i, err = receiver.ReadMessage(buf[:0], msg)
		assert.NoError(t, err)

		if cs1r != nil && cs2r != nil && cs1i != nil && cs2i != nil {

			assert.Equal(t, sender.ChannelBinding(), receiver.ChannelBinding())

			for j := 0; j < 10; j++ {
				var di, dr []byte

				ei := cs1i.Encrypt(buf[:0], nil, msg)
				dr, err = cs1r.Decrypt(buf[:0], nil, ei)
				assert.NoError(t, err)
				assert.Equal(t, dr, msg)

				er := cs2r.Encrypt(buf[:0], nil, msg)
				di, err = cs2i.Decrypt(buf[:0], nil, er)
				assert.NoError(t, err)
				assert.Equal(t, di, msg)
			}

			break
		} else {
			sender, receiver = receiver, sender
		}

	}
}
