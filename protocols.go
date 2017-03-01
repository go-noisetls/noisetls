package noisetls

import (
	"math"

	"github.com/flynn/noise"
)

//supported primitives

var dhFuncs = []noise.DHFunc{noise.DH25519}
var ciphers = []noise.CipherFunc{noise.CipherAESGCM, noise.CipherChaChaPoly}
var hashes = []noise.HashFunc{noise.HashSHA256, noise.HashBLAKE2b, noise.HashSHA512, noise.HashBLAKE2s}

type HandshakeConfig struct {
	Pattern         noise.HandshakePattern
	DH              noise.DHFunc
	Cipher          noise.CipherFunc
	Hash            noise.HashFunc
	Name            []byte
	NameLength      byte
	NameKey         uint64
	UseRemoteStatic bool
}

type PatternConfig struct {
	noise.HandshakePattern
	UseRemoteKey bool
}

// Go does not allow slices as keys, so we use siphash for map key
var handshakeConfigs map[uint64]*HandshakeConfig
var patternConfigs = []PatternConfig{{
	HandshakePattern: noise.HandshakeXX,
}, {
	HandshakePattern: noise.HandshakeIK,
	UseRemoteKey:     true,
}}

var protoPriorities = []string{noise.HandshakeIK.Name, noise.HandshakeXX.Name}

// preffered order of ciphersuites for each pattern
var protoCipherPriorities = make(map[string][]uint64)

//a separate prologue for each pattern. The count of entries in cipherSuitePriorities is equal to the amount of entries,
// used to form the corresponding prologue
var prologues = make(map[string][]byte)

func init() {
	handshakeConfigs = make(map[uint64]*HandshakeConfig)

	for _, pattern := range patternConfigs {

		prologues[pattern.Name] = make([]byte, 0, 512)
		protoCipherPriorities[pattern.Name] = make([]uint64, 0, 8)
		for _, dh := range dhFuncs {
			for _, c := range ciphers {
				for _, h := range hashes {

					name := []byte("Noise_" + pattern.Name + "_" + dh.DHName() + "_" + c.CipherName() + "_" + h.HashName())

					if len(name) > math.MaxUint8 {
						panic("message type name length exceeds 255 bytes")
					}

					nameKey := hashKey(name)

					if _, exists := handshakeConfigs[nameKey]; exists {
						panic("duplicate name hash!")
					}

					handshakeConfigs[nameKey] = &HandshakeConfig{
						Name:            name,
						NameLength:      byte(len(name)),
						Pattern:         pattern.HandshakePattern,
						DH:              dh,
						Cipher:          c,
						Hash:            h,
						NameKey:         nameKey,
						UseRemoteStatic: pattern.UseRemoteKey,
					}
					protoCipherPriorities[pattern.Name] = append(protoCipherPriorities[pattern.Name], nameKey)
					prologues[pattern.Name] = append(prologues[pattern.Name], handshakeConfigs[nameKey].NameLength)
					prologues[pattern.Name] = append(prologues[pattern.Name], name...)
				}
			}
		}

		if len(protoCipherPriorities[pattern.Name]) > math.MaxUint8 {
			panic("too many message types for a single pattern")
		}
	}
}
