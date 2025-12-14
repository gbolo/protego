package httpserver

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

func GetFiberApp(appName string, enableAccessLog bool, enableCompression bool, enableProfiler bool) (app *fiber.App) {
	app = fiber.New(fiber.Config{
		// app name
		AppName: appName,
		// When set to true, this will spawn multiple Go processes listening on the same port.
		Prefork: false,
		// Enables the "Server: value" HTTP header.
		ServerHeader: "protego",
		// When set to true, the router treats "/foo" and "/foo/" as different.
		StrictRouting: false,
		// When set to true, enables case sensitive routing.
		CaseSensitive: false,
		// The amount of time allowed to read the full request including body.
		ReadTimeout: time.Second * 15,
		// The maximum amount of time to wait for the next request when keep-alive is enabled.
		IdleTimeout: time.Second * 60,
		// When set to true, it will not print out the «Fiber» ASCII art and listening address.
		DisableStartupMessage: true,
		// If set to true, will print all routes with their method, path and handler.
		EnablePrintRoutes: false,

		// Important for nginx reverse proxy to get real IP
		EnableTrustedProxyCheck: false,
		ProxyHeader:             "X-Real-IP",
	})

	// inject middleware
	addFiberMiddlewareRecover(app)
	if enableAccessLog {
		addFiberMiddlewareLogger(app)
	}
	addFiberMiddlewareRequestID(app)
	if enableCompression {
		addFiberMiddlewareCompression(app)
	}
	addFiberMiddlewareEtag(app)
	if enableProfiler {
		addFiberMiddlewareMetrics(app)
	}
	addFiberMiddlewareFavicon(app)

	return
}

// Recover from panics
func addFiberMiddlewareRecover(app *fiber.App) {
	app.Use(recover.New())
}

// tweak the logging format
func addFiberMiddlewareLogger(app *fiber.App) {
	app.Use(logger.New(logger.Config{
		Format: "accessLog: ${ip} - ${locals:requestid} - [${time}] ${method} ${path} ${status} ${bytesSent} ${latency} \"${ua}\"\n",
	}))
}

// Adds an identifier to the response in the header
func addFiberMiddlewareRequestID(app *fiber.App) {
	app.Use(requestid.New(requestid.Config{
		Header: "X-Protego-Request-Id",
	}))
}

// Enables compression support for our http responses
func addFiberMiddlewareCompression(app *fiber.App) {
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed, // weak but fast
	}))
}

// Adds an E-Tag header. Useful if we are serving static content
func addFiberMiddlewareEtag(app *fiber.App) {
	app.Use(etag.New(etag.Config{
		Weak: true,
	}))
}

// Adds an endpoint (/debug/metrics) that reports server metrics
func addFiberMiddlewareMetrics(app *fiber.App) {
	app.Get("/debug/metrics", monitor.New(monitor.Config{Title: fmt.Sprintf("%s Metrics UI", app.Config().AppName)}))
}

// Ignores favicon requests or caches a provided icon in memory to improve performance by skipping disk access
func addFiberMiddlewareFavicon(app *fiber.App) {
	app.Use(favicon.New())
}
