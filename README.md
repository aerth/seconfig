# seconfig

### usage

#### **Step One**

Create and initialize a config struct with data. You make your own Config type with its own fields.

Sorry, no func or chan fields!

Note: Only Exported fields will be used by seconfig. (just like encoding/json package)

```
// Config structs can be named anything, and contain at least one Exported field
type Config struct {
	Interface string
	Port      int
	Name      string
}

  config := Config{
    Interface: "0.0.0.0",
    Port:      8080,
    Name:      "my server",
  }

```
#### **Step Two**

Marshal and encrypt your struct into a slice of encrypted bytes.  You will need the key provided here to access the data again.

```
	// encrypt the config struct into b []byte for you to save as you wish
	b, err := seconfig.Key([]byte("your-pass-phrase")).Lock(config)
	if err != nil {
		panic(err)
	}
```

#### **Step Three**

Decrypt and unmarshal the data with your new struct pointer. The pass phrase must be correct.

```
// decrypt and unmarshal the data with your new struct pointer. The pass phrase must be correct.
myconfig := new(Config)
err = seconfig.Key([]byte("your-pass-phrase")).Unlock(b, &myconfig)
pretty.Println(myconfig)
```

#### How To: **Raw Decode**

Decrypt the data into a raw bytes. It will be JSON encoded. The pass phrase must be correct.

```
b, err := Key([]byte("your-pass-phrase")).UnlockRaw(data)
```
