# seconfig

Lock your program's config file

## **warnings**

  * Needs security audit, code review.
  * Will most likely have breaking, backwards-incompatible-changes until stable.
  * It is up to your application to retrieve user input and handle hashing.
  * Key size must be 32 bytes. You can use the provided hash package to achieve this.
  * Probably not safe to use yet. Pull requests welcome.

## **usage**

You provide your own GetUserInput() method to receive password from input or environment

#### **Step One**

Create and initialize a config struct with data. You make your own Config type with its own fields.

Sorry, no func or chan fields, limited by `json` package.

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

##### Encryption

Marshal and encrypt the config struct into a slice of encrypted bytes.

Use `github.com/aerth/seconf/hash` package:

```
// pick a salt. not []byte{0,4,2,8}.
password := GetUserInput()
hashed := hash.Scrypt([]byte(password), []byte{0, 4, 2, 8})
```

Implement your own **Hashing**:

```
keyBytes := Hash(GetUserInput()) // get 32 byte key
b, err := seconfig.Key(keyBytes)).Marshal(config)
```

Or, use **Padding**:

```
b, err := seconfig.Pad("12341234123412341234123412341234").Key(GetUserInput()).Marshal(config)
```

#### **Step Three**

##### Decryption

Unmarshal the data into a config struct using **Unlock()**:

```
myconfig := new(Config)
err := seconfig.Key(GetUserInput()).Unlock(b, &myconfig)
```

or, decrypt using **Raw()**:

```
locked := seconfig.Key(GetUserInput()).RawLock(b)
unlocked := seconfig.Key(GetUserInput()).Raw(b)
```
