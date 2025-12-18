package server

import (
	"io"
	"net/http"

	"github.com/gbolo/protego/asset"
	_ "github.com/gbolo/protego/docs"
	"github.com/gbolo/protego/embedded"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/swagger"
)

// setupFiberRoutes configures all routes for the Fiber app
func setupFiberRoutes(app *fiber.App) {
	// API v1 routes
	apiV1 := app.Group("/api/v1")

	// Version endpoint
	apiV1.Get("/version", fiberHandlerVersion)

	// Config endpoint
	apiV1.Get("/config", fiberHandlerConfig)

	// Authorization endpoint
	apiV1.Get("/authorize", fiberHandlerAuthorize)

	// Challenge endpoint
	apiV1.Post("/challenge", fiberHandlerChallenge)

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

	// Admin UI
	app.Get("/admin", func(c *fiber.Ctx) error {
		file, err := asset.Assets.Open("/admin.html")
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
	})

	// Serve static files
	app.Use("/", filesystem.New(filesystem.Config{
		Root:       http.FS(embedded.FS),
		PathPrefix: "",
		Browse:     false,
	}))
}
