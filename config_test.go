package seconfig

import (
	"io/ioutil"
	"testing"
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
	b, err := Key([]byte("This is my password for testing things")).Lock(myconfig)
	checkerr(t, err)
	t.Log("Your encrypted config data:")
	t.Log(b)
	// write to file
	//err = ioutil.WriteFile("testdata/testconfig1.dat", b, 0600)
	//checkerr(t, err)
}

func TestUnlock(t *testing.T) {

	// initialize new empty config struct
	myconfig := new(testconfig1)

	// read encrypted data from file
	b, err := ioutil.ReadFile("testdata/testconfig1.dat")
	checkerr(t, err)

	// unlock with pass phrase
	err = Key([]byte("This is my password for testing things")).Unlock(b, &myconfig)
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
	err = Key([]byte("This is the wrong password")).Unlock(b, &myconfig)
	if err == nil {
		t.Log("Expected an error...")
	}
	if err.Error() != "Wrong pass phrase?" {
		t.Log("Expected error: \"Wrong pass phrase?\"")
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
