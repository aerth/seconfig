# seconfig

Lock your program's config file

### usage

#### **Step One**

Create and initialize a config struct with data. You make your own Config type with its own fields.

Sorry, no func or chan fields!

```
type Config struct {
  Interface string,
  Port int,
  Name string,
}
config := Config{
  Interface: "0.0.0.0",
  Port:      8080,
  Name:      "my server",
}

```
#### **Step Two**

Marshal and encrypt the config struct into a slice of encrypted bytes.  You will need the key provided here to access the data again.

```
b, err := Key([]byte("your-pass-phrase")).Lock(config)
```

#### **Step Three**

Decrypt and unmarshal the data into a config struct. The pass phrase must be correct.

```
myconfig := new(Config)
err = Key([]byte("your-pass-phrase")).Unlock(b, &myconfig)
```

#### **Raw Decode**

Decrypt the data into a raw bytes. It will be JSON encoded. The pass phrase must be correct.

```
b, err := Key([]byte("your-pass-phrase")).UnlockRaw(data)
```
