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
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/aerth/seconfig/hash"
)

type testconfig1 struct {
	Interface string
	Port      int
	Name      string
}

type testconfig2 struct {
	Bad func() error
}
type testconfig3 struct {
	AnotherBad chan int
}

func TestLock(t *testing.T) {

	// initialize a config struct with data
	myconfig := testconfig1{
		Interface: "0.0.0.0",
		Port:      8080,
		Name:      "my server",
	}

	// marshal and encrypt
	b, err := Key([]byte("This is my password for testing ")).Lock(myconfig)
	checkerr(t, err)
	t.Log("Your encrypted config data:")
	t.Log(b)
	// write to file
	//err = ioutil.WriteFile("testdata/testconfig1.dat", b, 0600)
	//checkerr(t, err)
}

func TestLockHash(t *testing.T) {

	// initialize a config struct with data
	myconfig := testconfig1{
		Interface: "0.0.0.0",
		Port:      8080,
		Name:      "my server",
	}

	// marshal and encrypt
	b, err := Key([]byte(hash.Scrypt([]byte("This is my password for testing things and its really long"), []byte{0, 4, 2, 8}))).Lock(myconfig)
	checkerr(t, err)
	t.Log("Your encrypted config data:")
	t.Log(b)
	//write to file
	// err = ioutil.WriteFile("testdata/testconfig2.dat", b, 0600)
	// checkerr(t, err)
}

func TestRawLockHash(t *testing.T) {
	message := []byte("hello world")
	b := Key([]byte(hash.Scrypt([]byte("This is my password for testing things and its really long"), []byte{0, 1, 0, 8}))).RawLock(message)
	t.Log("Your encrypted data:")
	t.Log(b)
	//write to file
	//err := ioutil.WriteFile("testdata/testconfig3.dat", b, 0600)
	//checkerr(t, err)

	b2, err := ioutil.ReadFile("testdata/testconfig3.dat")
	checkerr(t, err)
	unlocked := Key([]byte(hash.Scrypt([]byte("This is my password for testing things and its really long"), []byte{0, 1, 0, 8}))).Raw(b2)
	if bytes.Compare(message, unlocked) != 0 {
		t.Logf("Expected %x, Got %x", message, unlocked)
		t.Fail()
	}
}

func TestUnlock(t *testing.T) {

	// initialize new empty config struct
	myconfig := new(testconfig1)

	// read encrypted data from file
	b, err := ioutil.ReadFile("testdata/testconfig1.dat")
	checkerr(t, err)

	// unlock with pass phrase
	err = Key([]byte("This is my password for testing ")).Unlock(b, &myconfig)
	checkerr(t, err)

	// display config
	t.Log("Your config data:")
	t.Logf("Interface: \"%s\"\n", myconfig.Interface)
	t.Logf("Port: \"%v\"\n", myconfig.Port)
	t.Logf("Name: \"%s\"\n", myconfig.Name)

	// check fields
	if myconfig.Interface != "0.0.0.0" {
		t.Log("Expected interface to be 0.0.0.0")
		t.Fail()
	}
	if myconfig.Port != 8080 {
		t.Log("Expected port to be 8080, its:", myconfig.Port)
		t.Fail()
	}

	if myconfig.Name != "my server" {
		t.Log("Expected name to be \"my server\"")
		t.Fail()
	}
}
func TestUnlockHash(t *testing.T) {

	// initialize new empty config struct
	myconfig := new(testconfig1)

	// read encrypted data from file
	b, err := ioutil.ReadFile("testdata/testconfig2.dat")
	checkerr(t, err)

	// unlock with pass phrase
	err = Key([]byte(hash.Scrypt([]byte("This is my password for testing things and its really long"), []byte{0, 4, 2, 8}))).Unlock(b, &myconfig)
	checkerr(t, err)

	// display config
	t.Log("Your config data:")
	t.Logf("Interface: \"%s\"\n", myconfig.Interface)
	t.Logf("Port: \"%v\"\n", myconfig.Port)
	t.Logf("Name: \"%s\"\n", myconfig.Name)

	// check fields
	if myconfig.Interface != "0.0.0.0" {
		t.Log("Expected interface to be 0.0.0.0")
		t.Fail()
	}
	if myconfig.Port != 8080 {
		t.Log("Expected port to be 8080, its:", myconfig.Port)
		t.Fail()
	}

	if myconfig.Name != "my server" {
		t.Log("Expected name to be \"my server\"")
		t.Fail()
	}
}

func TestUnlockBadPassword(t *testing.T) {
	myconfig := new(testconfig1)
	b, err := ioutil.ReadFile("testdata/testconfig1.dat")
	checkerr(t, err)
	err = Key([]byte("This is the wrong password - - -")).Unlock(b, &myconfig)
	if err == nil {
		t.Log("Expected an error...")
	}
	if err != ErrWrongKey {
		t.Log("Expected error:", ErrWrongKey)
		t.Log("Got error:", err)
	}
}

// Test for struct fields that are unable to be marshalled
func TestBadJSON(t *testing.T) {
	myconfig := testconfig2{}
	_, err := Key([]byte("password123")).Lock(myconfig)
	if err == nil {
		t.Log("expected an error")
		t.FailNow()
	}
	t.Log("Good error:", err)
	myconfig3 := testconfig3{}
	_, err = Key([]byte("password123")).Lock(myconfig3)
	if err == nil {
		t.Log("expected an error")
		t.FailNow()
	}
	t.Log("Good error:", err)
}

// make life easier but ruin the log traceback
func checkerr(t *testing.T, err error) {
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
}

func TestKeySize(t *testing.T) {
	defer testPanic(t)()
	myshortkey := []byte("hunter123")
	myconfig := "JustASimpleApiKey"
	b, err := Key(myshortkey).Lock(myconfig)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("0x%x\n", b)
	t.FailNow()
}
func TestKeySizeRead(t *testing.T) {
	defer testPanic(t)()
	myshortkey := []byte("hunter123")
	myconfig := new(testconfig1)
	encrypted, err := ioutil.ReadFile("testdata/testconfig1.dat")
	checkerr(t, err)
	err = Key(myshortkey).Unlock(encrypted, &myconfig)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(myconfig)
	t.FailNow()
}

func testPanic(t *testing.T) func() {
	return func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}
}
