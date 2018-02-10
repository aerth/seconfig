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
	"runtime"

	"github.com/aerth/ppanic"
	"github.com/aerth/seconfig"
)

// data is a demo struct
type data struct {
	OS, Arch string
}

func init() {
	// be sure to change pad
	seconfig.Pad = "This is the default pad for this example."
}

func main() {
	// lock data (in this case using OS and architecture)
	println("Enter a dummy pass phrase. It will echo.")
	key := "password"
	fmt.Scan(&key)
	b, err := seconfig.Key(key).Lock(data{runtime.GOOS, runtime.GOARCH})
	if err != nil {
		ppanic.Panic(err)
	}
	fmt.Printf("Encrypted data: \"%s\"\n", string(b))
	fmt.Println()

	// unlock raw
	println("Enter the same dummy pass phrase to unlock. It will echo.")
	fmt.Scan(&key)
	b = seconfig.Key(key).Raw(b)
	if b == nil {
		ppanic.Exit("wrong passphrase?")
	}
	fmt.Printf("Decrypted data: \"%s\"\n", string(b))

	// unlock a struct
	databyte := data{}
	err = seconfig.Key(key).Unlock(b, &databyte)
	if err != nil {
		ppanic.Exit(err)
	}
	fmt.Printf("OS: %s\nArch: %s\n", databyte.OS, databyte.Arch)
}
