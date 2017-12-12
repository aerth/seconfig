package seconfig

import (
	"encoding/json"
	"fmt"
)

// how to make a easy to use universal encrypted config file?

// Key holds the password. You can use it like this:
//   seconf.Key([]byte("mypassword").Marshal(myConfigStruct)
//   seconf.Key([]byte("mypassword").Unmarshal(myEncryptedConfig)
type Key []byte

// Lock acts like JSON Marshal, but only can be seen after using seconf.Unlock https://godoc.org/encoding/json#Marshal
func (c Key) Lock(v interface{}) (b []byte, err error) {
	b, err = json.Marshal(v)
	if err != nil {
		return b, err
	}
	return c.lock(b), nil
}

// Unlock acts like JSON Unmarshal, but decrypts the data before unmarshaling. https://godoc.org/encoding/json#Unmarshal
func (c Key) Unlock(data []byte, v interface{}) (err error) {
	if data == nil {
		return fmt.Errorf("Nothing to decode")
	}
	if b := c.unlock(data); b != nil {
		return json.Unmarshal(b, v)
	}
	return fmt.Errorf("Wrong pass phrase?")
}
