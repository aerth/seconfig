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

package hash

import (
	"fmt"
	"testing"
)

var salt = []byte{0x0, 0xa}
var cost = 1

func TestScrypt(t *testing.T) {
	pass := []byte("my test pass")
	hashmap := map[string]string{
		"scrypt":             "a4794f9d833ab5edda9ad7b961e6382166b1b89ea4f12431edc06ff2241d9a28",
		"sha256-salt-pepper": "fd2dc276a0310e63143b6ecc15ac22784a8b5dc4a92d178e0f11399bb8585ffb",
		"sha256":             "b78e232150042b0869b7e033cedbb226cd6f48ef36b70a95fdcea86621f587c8",
		"scrypt-slow":        "2cc36c378e3ce9a19d6415652d5f01d09917a8bc8a8719bb378a1f7f59e163e1",
	}

	gotmap := map[string]string{
		"scrypt":             fmt.Sprintf("%x", Scrypt(pass, []byte(salt))),
		"sha256-salt-pepper": fmt.Sprintf("%x", Sha256(pass, []byte{0x0}, []byte{0xa, 0x32})),
		"sha256":             fmt.Sprintf("%x", Sha256(pass, nil, nil)),
		"scrypt-slow":        fmt.Sprintf("%x", ScryptSlow(pass, []byte(salt))),
	}

	for test, pass := range hashmap {
		if gotmap[test] != pass {
			fmt.Printf("%s fail\nExpected: %q\nGot: %q\n", test, pass, gotmap[test])
			t.Fail()
		}
	}

}
