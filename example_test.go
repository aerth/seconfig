package seconfig

import (
	"crypto/sha256"
	"fmt"
)

func ExamplePad_Key() {
	dummyPad := [32]byte{} // zero filled, dont do this.
	p := Pad(dummyPad[:])
	k := p.Key([]byte("pass")) // provide pass phrase
	fmt.Printf("%x\n", k)
	k = p.Key([]byte("p"))
	fmt.Printf("%x\n", k)
	// Output:
	// 7061737300000000000000000000000000000000000000000000000000000000
	// 7000000000000000000000000000000000000000000000000000000000000000
}

func ExampleKey_RawLock() {
	hash := sha256.Sum256([]byte("password"))
	k := Key(hash[:])
	b := k.RawLock([]byte("hello"))
	fmt.Printf("hello = %x\n", b)
	// Can't compare Output here because the encrypted data comes out different every time.
}

func ExampleKey_Raw() {
	encrypted := []byte{0x80, 0x79, 0x36, 0x33, 0x94, 0x26, 0xd0, 0x5f, 0x2d, 0x4c, 0x9b, 0xb2, 0x63, 0x1b, 0x2b, 0x47, 0x57, 0x6d, 0x5, 0x5d, 0x43, 0x79, 0xc0, 0x59, 0xd7, 0x53, 0x3b, 0xf4, 0xcd, 0x53, 0xc5, 0xb3, 0x6c, 0xf5, 0x62, 0x8c, 0x45, 0x38, 0x47, 0x4f, 0x9b, 0xee, 0x19, 0x93, 0xf0}
	password := sha256.Sum256([]byte("password"))
	key := Key(password[:])
	decrypted := key.Raw(encrypted)
	fmt.Println(string(decrypted))
	// Output:
	// hello
}
