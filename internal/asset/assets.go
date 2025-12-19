//go:build !dev
// +build !dev

package asset

import (
	"net/http"

	"github.com/gbolo/protego/internal/embedded"
)

// Assets contains project assets.
var Assets http.FileSystem = embedded.HTTPFileSystem()
