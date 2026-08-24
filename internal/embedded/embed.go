package embedded

import (
	"embed"
	"io/fs"
)

// The embedded content is deliberately split into three trees so that each HTTP
// listener can only ever serve the files it is supposed to:
//
//	public/ -- the challenge UI, served on the public listener
//	admin/  -- the admin UI, served on the admin listener only
//	assets/ -- shared images (favicon, logo), served on both
//
// Note that the patterns below are explicit rather than a wildcard: a bare
// "//go:embed *" would also embed this source file, which then becomes
// retrievable over HTTP by the static file middleware.

//go:embed public
var publicFS embed.FS

//go:embed admin
var adminFS embed.FS

//go:embed assets
var assetsFS embed.FS

// Public returns the challenge UI file system, rooted at public/.
func Public() fs.FS { return mustSub(publicFS, "public") }

// Admin returns the admin UI file system, rooted at admin/.
func Admin() fs.FS { return mustSub(adminFS, "admin") }

// Assets returns the shared image file system, rooted at assets/.
func Assets() fs.FS { return mustSub(assetsFS, "assets") }

// mustSub returns the sub file system rooted at dir. The go:embed directives
// above guarantee that dir exists, so a failure here is a programming error.
func mustSub(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic("embedded: unable to open sub filesystem " + dir + ": " + err.Error())
	}
	return sub
}
