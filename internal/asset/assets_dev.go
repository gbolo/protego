//go:build dev
// +build dev

// This ONLY gets compiled when using the go build tag "dev"
// The purpose of this tag is to ensure that static files come from disk during development for convenience
package asset

import "net/http"

// Project assets, split per listener. See internal/embedded/embed.go.
var (
	// PublicFS holds the challenge UI, safe to serve publicly.
	PublicFS http.FileSystem = http.Dir("../embedded/public")
	// AdminFS holds the admin UI and must only be served on the admin listener.
	AdminFS http.FileSystem = http.Dir("../embedded/admin")
	// AssetsFS holds shared images and is served on both listeners.
	AssetsFS http.FileSystem = http.Dir("../embedded/assets")
)
