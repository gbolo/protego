//go:build !dev
// +build !dev

package asset

import (
	"net/http"

	"github.com/gbolo/protego/internal/embedded"
)

// Project assets, split per listener. See internal/embedded/embed.go.
var (
	// PublicFS holds the challenge UI, safe to serve publicly.
	PublicFS http.FileSystem = http.FS(embedded.Public())
	// AdminFS holds the admin UI and must only be served on the admin listener.
	AdminFS http.FileSystem = http.FS(embedded.Admin())
	// AssetsFS holds shared images and is served on both listeners.
	AssetsFS http.FileSystem = http.FS(embedded.Assets())
)
