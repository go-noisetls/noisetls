package noisetls

import (
	"strings"

	"github.com/flynn/noise"
)

type CipherSuite struct {
	name        string
	cipherSuite noise.CipherSuite
}

type SuiteSet struct {
	cipherSuite noise.CipherSuite
	message     []byte
}

var cipherSuites map[string]*CipherSuite
var cipherSuitePriority []string
var prologue []byte

func init() {
	cipherSuites = make(map[string]*CipherSuite)
	csName := make([]string, 4)
	csName[0] = "NoiseSocket"
	prologue = make([]byte, 1)
	for _, dh := range dhFuncs {
		for _, c := range ciphers {
			for _, h := range hashes {
				csName[1] = dh.DHName()
				csName[2] = c.CipherName()
				csName[3] = h.HashName()
				name := strings.Join(csName, "_")

				cipherSuites[name] = &CipherSuite{
					name:        name,
					cipherSuite: noise.NewCipherSuite(dh, c, h),
				}
				prologue[0]++ // increment versions count
				l := len(name)
				if l > 255 {
					panic("protolol version length cannot exceed 255 bytes")
				}

				prologue = append(prologue, byte(l))
				prologue = append(prologue, name...)
				cipherSuitePriority = append(cipherSuitePriority, name)
			}
		}
	}

}
