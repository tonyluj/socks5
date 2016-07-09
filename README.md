# Go socks5 library

[SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS) in Go.

## Feature

* Support No Auth
* Support CONNECT cmd

## TODO
- [ ] Unit Test
- [ ] Password Auth
- [ ] Support BIND cmd
- [ ] Support UDP
- [ ] Support Custome DNS

## Example

```go
package main

import (
        "log"
        "time"

        "github.com/tonyluj/socks5"
)

func main() {
        s, err := socks5.New(":8080", time.Second*5*60)
        if err != nil {
                log.Fatal(err)
        }

        err = s.Listen()
        if err != nil {
                log.Fatal(err)
        }
}

```
