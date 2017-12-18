package seconfig

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const nonceSize = 24
const keySize = 32

// Key holds the password. You can use it like this:
//   data := seconfig.Key([]byte("mypassword").Lock(struct{})
//   seconfig.Key([]byte("mypassword").UnlockRaw(data)
type Key []byte

// Lock acts like JSON Marshal, but only can be seen after using seconfig.Unlock
// More info on JSON marshal here: https://godoc.org/encoding/json#Marshal
func (c Key) Lock(v interface{}) (b []byte, err error) {
	b, err = json.Marshal(v)
	if err != nil {
		return b, err
	}
	return c.lock(b), nil
}

// LockRaw encrypts data with key
// For when you want to modify your JSON or use another encoding for marshal.
func (c Key) LockRaw(data []byte) (b []byte, err error) {
	return c.lock(b), nil
}

// Unlock acts like JSON Unmarshal, but decrypts the data before unmarshaling.
// More info on JSON unmarshal here: https://godoc.org/encoding/json#Unmarshal
func (c Key) Unlock(data []byte, v interface{}) (err error) {
	b, err := c.UnlockRaw(data)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}

// UnlockRaw returns raw data.
// For when you need JSON encoded data back, or have used seconfig.LockRaw
func (c Key) UnlockRaw(data []byte) ([]byte, error) {
	if data == nil || len(data) < nonceSize {
		return nil, fmt.Errorf("check input")
	}
	if b := c.unlock(data); b != nil {
		return b, nil
	}
	return nil, fmt.Errorf("wrong pass phrase?")
}

func hash(in []byte) [keySize]byte {
	salt := []byte{0x42, 0x9f, 0xbe, 0xde, 0xad, 0x0a, 0x23, 0x74}
	N := 2 << 16
	r := 8
	p := 1
	b32, err := scrypt.Key(in, salt, N, r, p, keySize)
	if err != nil {
		panic(fmt.Sprintf("fatal: could not scrypt: %s", err))
	}
	h := new([keySize]byte)
	copy(h[:], b32)
	return *h
}
func (c Key) lock(b []byte) []byte {
	key := []byte(c)
	naclKey := hash(key)
	nonce := new([nonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic(fmt.Sprintf("Could not read from random: %s", err))
	}
	out := make([]byte, nonceSize)
	copy(out, nonce[:])
	return secretbox.Seal(out, b, nonce, &naclKey)
}

func (c Key) unlock(b []byte) []byte {
	key := []byte(c)
	naclKey := hash(key)
	nonce := new([nonceSize]byte)
	copy(nonce[:], b[:nonceSize])
	configbytes, _ := secretbox.Open(nil, b[nonceSize:], nonce, &naclKey)
	return configbytes
}
