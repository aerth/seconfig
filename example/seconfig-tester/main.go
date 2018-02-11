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

// Usage demo for seconfig package (https://github.com/aerth/seconfig)
package main

import (
	"fmt"
	"log"
	"runtime"

	"github.com/aerth/seconfig"
	"github.com/aerth/seconfig/hash"
)

// data is a demo struct
type data struct {
	OS, Arch string
}

func main() {
	log.SetFlags(log.Lshortfile)
	HashUsage()
	PadUsage()
}
func PadUsage() {
	println("\n\nPad Method\n\n")
	// lock data (in this case using OS and architecture)
	padlock := seconfig.Pad("This is the default pad for this example.")
	println("Enter a dummy pass phrase. It will echo.")
	key := []byte("password")
	fmt.Scan(&key)
	b, err := padlock.Key(key).Lock(data{runtime.GOOS, runtime.GOARCH})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Encrypted data: \"%s\"\n", string(b))
	fmt.Println()

	// unlock raw
	println("Enter the same dummy pass phrase to unlock. It will echo.")
	fmt.Scan(&key)
	b = padlock.Key(key).Raw(b)
	if b == nil {
		log.Println("wrong passphrase?")
		return
	}
	fmt.Printf("Decrypted (raw) data: \"%s\"\n", string(b))

	// unlock a struct
	databyte := data{}
	err = padlock.Key(key).Unlock(b, &databyte)
	if err != nil {
		log.Println("pad error:", err)
		return
	}
	fmt.Printf("OS: %s\nArch: %s\n", databyte.OS, databyte.Arch)
}
func HashUsage() {
	// lock data (in this case using OS and architecture)
	println("\n\nHash Method\n\n")
	println("Enter a dummy pass phrase. It will echo.")
	var key []byte
	fmt.Scan(&key)
	salt := []byte{255, 240, 0, 1}
	b, err := seconfig.Key(hash.Scrypt(key, salt)).Lock(data{runtime.GOOS, runtime.GOARCH})
	if err != nil {
		log.Println(err)
		return
	}
	key = []byte{}
	fmt.Printf("Encrypted data: \"%s\"\n", string(b))
	fmt.Println()

	// unlock raw
	println("Enter the same dummy pass phrase to unlock. It will echo.")
	fmt.Scan(&key)
	unraw := seconfig.Key(hash.Scrypt(key, salt)).Raw(b)
	if unraw == nil {
		log.Println("wrong passphrase?")
		return
	}
	fmt.Printf("Decrypted data: \"%s\"\n", string(unraw))

	// unlock a struct
	databyte := data{}
	err = seconfig.Key(hash.Scrypt(key, salt)).Unlock(b, &databyte)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("OS: %s\nArch: %s\n", databyte.OS, databyte.Arch)
}
