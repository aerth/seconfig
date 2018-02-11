package seconfig

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const keySize = 32
const nonceSize = 24

type Pad []byte

// Key padding for non hashers
func (p Pad) Key(key []byte) Key {
	if len(key) < keySize { // padding
		key = append(key, []byte(p[:keySize-len(key)])...)
	}
	return Key(key)
}

func (c Key) lock(b []byte) []byte {
	key := []byte(c)
	if len(key) != keySize {
		panic(fmt.Sprintf("key size: %v != %v", len(key), keySize))
	}
	naclKey := new([keySize]byte)
	copy(naclKey[:], key[:keySize]) // truncate to 32

	// fille nonce
	nonce := new([nonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic("Could not read from random: " + err.Error())
	}
	out := make([]byte, nonceSize)
	copy(out, nonce[:])

	// seal, return errors
	return secretbox.Seal(out, b, nonce, naclKey)
}

func (c Key) unlock(b []byte) []byte {
	key := []byte(c)
	if len(key) != keySize {
		panic(fmt.Sprintf("key size: %v != %v", len(key), keySize))
	}
	naclKey := new([keySize]byte)
	copy(naclKey[:], key[:keySize])
	nonce := new([nonceSize]byte)
	copy(nonce[:], b[:nonceSize]) // extract nonce
	// open secretbox
	configbytes, _ := secretbox.Open(nil, b[nonceSize:], nonce, naclKey)
	return configbytes
}
