package server

import (
	"io"

	_ "github.com/gbolo/protego/docs"
	"github.com/gbolo/protego/internal/asset"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/swagger"
)

// setupPublicRoutes configures the routes required for a user to complete a
// challenge and nothing else. Everything registered here is reachable from the
// internet, so keep this list as small as possible. Admin endpoints, the admin
// UI, the swagger docs, the metrics dashboard and the forward-auth endpoint all
// belong on the admin listener: see setupAdminRoutes.
func setupPublicRoutes(app *fiber.App) {
	apiV1 := app.Group("/api/v1")

	// the challenge page reads the version to render its footer
	apiV1.Get("/version", fiberHandlerVersion)
	apiV1.Get("/healthz", fiberHandlerHealthz)

	// Challenge endpoint: the reason this listener exists
	apiV1.Post("/challenge", fiberHandlerChallenge)

	// Shared images. Must be registered before the catch-all below.
	app.Use("/assets", filesystem.New(filesystem.Config{
		Root:   asset.AssetsFS,
		Browse: false,
	}))

	// Challenge UI
	app.Use("/", filesystem.New(filesystem.Config{
		Root:   asset.PublicFS,
		Index:  "index.html",
		Browse: false,
	}))
}

// setupAdminRoutes configures the admin API, the admin UI, the swagger docs and
// the forward-auth endpoint. This listener trusts a client supplied X-Real-IP
// header and serves unauthenticated diagnostics, so it must never be publicly
// reachable. Bind it to loopback or a private network.
func setupAdminRoutes(app *fiber.App) {
	apiV1 := app.Group("/api/v1")

	apiV1.Get("/version", fiberHandlerVersion)
	apiV1.Get("/healthz", fiberHandlerHealthz)

	// Config endpoint
	apiV1.Get("/config", fiberHandlerConfig)

	// Authorization endpoint: called by the reverse proxy, not by users
	apiV1.Get("/authorize", fiberHandlerAuthorize)

	// User management endpoints
	apiV1.Post("/user", fiberHandlerUserAdd)
	apiV1.Put("/user/:id", fiberHandlerUserUpdate)
	apiV1.Get("/user/:id", fiberHandlerUserGet)
	apiV1.Get("/user", fiberHandlerUserGetAll)
	apiV1.Delete("/user/:id", fiberHandlerUserDelete)

	// ACL management endpoints
	apiV1.Post("/acl/:ip", fiberHandlerACLAdd)
	apiV1.Put("/acl/:ip", fiberHandlerACLUpdate)
	apiV1.Get("/acl/:ip", fiberHandlerACLGet)
	apiV1.Get("/acl", fiberHandlerACLGetAll)
	apiV1.Delete("/acl/:ip", fiberHandlerACLDelete)

	// Swagger documentation
	app.Get("/swagger/*", swagger.HandlerDefault)

	// Admin UI. Also served at the root of this listener by the catch-all below,
	// this route is kept so the historical /admin path keeps working.
	app.Get("/admin", fiberHandlerAdminUI)

	// Shared images. Must be registered before the catch-all below.
	app.Use("/assets", filesystem.New(filesystem.Config{
		Root:   asset.AssetsFS,
		Browse: false,
	}))

	// Admin UI static files (admin.html, admin.css, admin.js)
	app.Use("/", filesystem.New(filesystem.Config{
		Root:   asset.AdminFS,
		Index:  "admin.html",
		Browse: false,
	}))
}

// fiberHandlerAdminUI serves the admin UI page.
func fiberHandlerAdminUI(c *fiber.Ctx) error {
	file, err := asset.AdminFS.Open("/admin.html")
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("Admin page not found")
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Error reading admin page")
	}

	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.Send(content)
}
