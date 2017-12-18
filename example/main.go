package main

import (
	"github.com/aerth/seconfig"
	"github.com/kr/pretty"
)

// Config structs can be named anything, and contain at least one Exported field
type Config struct {
	Interface string
	Port      int
	Name      string
}

func main() {
	// initialize config by user input
	config := Config{
		Interface: "0.0.0.0",
		Port:      8080,
		Name:      "my server",
	}

	// encrypt the config struct into b []byte for you to save as you wish
	b, err := seconfig.Key([]byte("your-pass-phrase")).Lock(config)
	if err != nil {
		panic(err)
	}
	// decrypt and unmarshal the data with your new struct pointer. The pass phrase must be correct.
	myconfig := new(Config)
	err = seconfig.Key([]byte("your-pass-phrase")).Unlock(b, &myconfig)

	pretty.Println(myconfig)

}
