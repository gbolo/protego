// +build dev

// This ONLY gets compiled when using the go build tag "dev"
// The purpose of this tag is to ensure that static files come from disk during development for convenience
package asset

import "net/http"

// Assets contains project assets.
var Assets http.FileSystem = http.Dir("../embedded")