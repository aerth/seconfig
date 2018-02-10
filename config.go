package seconfig

import (
	"encoding/json"
	"fmt"
)

// how to make a easy to use universal encrypted config file?

// Key holds the password. You can use it like this:
//   seconf.Key([]byte("mypassword").Marshal(myConfigStruct)
//   seconf.Key([]byte("mypassword").Unmarshal(myEncryptedConfig)
//
// It is up to the application to validate the key.
// Key size is 32 bits.
// If a key is too small, it will be padded using seconfig.Pad, which should be customized per application.
// If a key is too large, it will be truncated.
type Key []byte

// Lock acts like JSON Marshal, which contents can only be seen after using seconf.Unlock https://godoc.org/encoding/json#Marshal
func (c Key) Lock(v interface{}) (b []byte, err error) {
	b, err = json.Marshal(v)
	if err != nil {
		return b, err
	}
	return c.lock(b), nil
}

// Unlock acts like JSON Unmarshal, but decrypting the data before unmarshaling. https://godoc.org/encoding/json#Unmarshal
func (c Key) Unlock(data []byte, v interface{}) (err error) {
	if data == nil {
		return fmt.Errorf("Nothing to decode")
	}
	if b := c.unlock(data); b != nil {
		return json.Unmarshal(b, v)
	}
	return fmt.Errorf("Wrong pass phrase?")
}

// Raw data as []byte
func (c Key) Raw(data []byte) []byte {
	if data == nil || len(data) == 0 {
		return nil
	}
	if b := c.unlock(data); b != nil {
		return b
	}
	return nil
}
