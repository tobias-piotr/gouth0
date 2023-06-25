# gouth0

[![Go Report Card](https://goreportcard.com/badge/github.com/tobias-piotr/gouth0)](https://goreportcard.com/report/github.com/tobias-piotr/gouth0)

Simple utils for working with Auth0 in Go. I've made this package for my personal use, but if you find any of this useful, then I'm glad it helped.

Take note that this package is not complete, and I'm adding features as I need them. Feel free to contribute.

Also, I've made the package after around five days of learning Go, so if you find any mistakes, please let me know.

## Installation

```bash
go get github.com/tobias-piotr/gouth0
```

## Usage

If you want to work with JWT tokens, first, you need to create a new instance of the `TokenService`:

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/tobias-piotr/gouth0"
)

func main() {
    ts := gouth0.NewTokenService(gouth0.ConfigFromEnv(), &http.Client{}, 60)
}
```

`ConfigFromEnv()` will read the environment variables and create a new `AuthConfig` struct. You can also create the `AuthConfig` struct manually:

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/tobias-piotr/gouth0"
)

func main() {
    ts := gouth0.NewTokenService(&gouth0.AuthConfig{
        Domain:     "your-domain.auth0.com",
        Audience:   "https://your-audience.com/",
        Algorithms: []string{"RS256"},
    }, &http.Client{}, 60)
}
```

With that in place, you can simply start decoding JWT tokens with the `DecodeToken` method:

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/tobias-piotr/gouth0"
)

func main() {
    ts := gouth0.NewTokenService(gouth0.ConfigFromEnv(), &http.Client{}, 60)
    decoded, err := ts.DecodeToken("your-jwt-token")
}
```

`decoded` will contain a map of the decoded token payload, and err can be any error encountered during the decoding process.
