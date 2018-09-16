/*
 * Copyright (c) 2017 aerth <aerth@riseup.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package seconfig

import (
	"encoding/json"
	"fmt"
)

// how to make a easy to use universal encrypted config file?

// Key holds the password. You can use it like this (but with 32 bytes for keys):
//   seconf.Key([]byte("my 32 byte key").Marshal(myConfigStruct)
//   seconf.Key([]byte("my 32 byte key").Unmarshal(myEncryptedConfig)
//
// It is up to the application to validate the key.
// Key size is 32 bytes.
// If a key is too small, it will be padded using seconfig.Pad, which should be customized per application.
// If a key is too large, it will be truncated.
type Key []byte

// Lock acts like JSON Marshal, which contents can only be seen after using seconf.Unlock https://godoc.org/encoding/json#Marshal
func (k Key) Lock(v interface{}) (b []byte, err error) {
	b, err = json.Marshal(v)
	if err != nil {
		return b, err
	}
	return k.lock(b), nil
}

// ErrWrongKey is returned by Unlock if no bytes were unencrypted
var ErrWrongKey = fmt.Errorf("wrong key?")

// ErrNoData is returned by Unlock if len(input) is zero
var ErrNoData = fmt.Errorf("no data")

// Unlock acts like JSON Unmarshal, but decrypting the data before unmarshaling.
// It returns ErrNoData if data is nil, or ErrWrongKey if unencryption failed.
// Finally, it returns JSON errors. https://godoc.org/encoding/json#Unmarshal
func (k Key) Unlock(data []byte, v interface{}) (err error) {
	if len(data) == 0 {
		return ErrNoData
	}

	b := k.unlock(data)

	if b == nil {
		return ErrWrongKey

	}
	return json.Unmarshal(b, v)
}

// Raw unlocks, skipping json marshalling, returning unencrypted data as []byte, or nil if decryption failed.
func (k Key) Raw(data []byte) []byte {
	if data == nil || len(data) == 0 {
		return nil
	}
	if b := k.unlock(data); b != nil {
		return b
	}
	return nil
}

// RawLock skips json marshalling, and returns the encrypted byte slice
func (k Key) RawLock(contents []byte) []byte {
	return k.lock(contents)
}

// Unmarshal is an alias for Unlock to implement your interface
func (k Key) Unmarshal(data []byte, v interface{}) error {
	return k.Unlock(data, v)
}

// Read is an alias for Unlock to implement your interface
func (k Key) Read(data []byte, v interface{}) error {
	return k.Unlock(data, v)
}

// Deserialize is an alias for Unlock to implement your interface
func (k Key) Deserialize(data []byte, v interface{}) error {
	return k.Unlock(data, v)
}

// Marshal is an alias for Lock to implement your interface
func (k Key) Marshal(v interface{}) (b []byte, err error) {
	return k.Lock(v)
}

// Write is an alias for Lock to implement your interface
func (k Key) Write(v interface{}) (b []byte, err error) {
	return k.Lock(v)
}

// Serialize is an alias for Lock to implement your interface
func (k Key) Serialize(v interface{}) (b []byte, err error) {
	return k.Lock(v)
}
