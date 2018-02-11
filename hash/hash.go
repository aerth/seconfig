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

// hash provides popular hash functions
package hash

import (
	"crypto/sha256"

	"golang.org/x/crypto/scrypt"
)

// Scrypt hash 32 bytes
func Scrypt(psw []byte, salt []byte) []byte {
	hash, _ := scrypt.Key(psw, salt, 1<<15, 8, 1, 32) // 32768
	return hash
}

// ScryptSlow hash 32 bytes
func ScryptSlow(psw []byte, salt []byte) []byte {
	hash, _ := scrypt.Key(psw, salt, 1<<16, 8, 1, 32)
	return hash
}

// Sha256Pepper salt+pass+pepper
func Sha256(psw, salt, pepper []byte) []byte {
	hash256 := sha256.Sum256(append(salt, append(psw, pepper...)...))
	return hash256[:]
}

// // Bcrypt min cost 4, max cost 31
// func Bcrypt(psw []byte, cost int) []byte {
// 	hash, _ := bcrypt.GenerateFromPassword(psw, cost)
// 	return hash
// }
