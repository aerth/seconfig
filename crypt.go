package seconfig

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const pad = "Make your_password long^like this!"
const keySize = 32
const nonceSize = 24

func (c Key) lock(b []byte) []byte {
	key := []byte(c)
	naclKey := new([keySize]byte)
	copy(naclKey[:], key[:keySize])
	nonce := new([nonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic("Could not read from random: " + err.Error())
	}
	out := make([]byte, nonceSize)
	copy(out, nonce[:])
	return secretbox.Seal(out, b, nonce, naclKey)
}

func (c Key) unlock(b []byte) []byte {
	key := []byte(c)
	naclKey := new([keySize]byte)
	copy(naclKey[:], key[:keySize])
	nonce := new([nonceSize]byte)
	copy(nonce[:], b[:nonceSize])
	configbytes, _ := secretbox.Open(nil, b[nonceSize:], nonce, naclKey)
	return configbytes
}
