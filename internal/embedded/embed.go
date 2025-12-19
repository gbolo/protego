package embedded

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed *
var FS embed.FS

// HTTPFileSystem returns an http.FileSystem for the embedded files
func HTTPFileSystem() http.FileSystem {
	return http.FS(FS)
}

// Sub returns a sub-filesystem
func Sub(dir string) (fs.FS, error) {
	return fs.Sub(FS, dir)
}
