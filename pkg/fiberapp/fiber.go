package fiberapp

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

// Options configures the Fiber app returned by GetFiberAppWithOptions.
type Options struct {
	// AppName is used for the app name, the "Server" response header and the
	// title of the metrics dashboard.
	AppName string
	// EnableMetrics registers the /metrics monitor dashboard. It is served
	// without authentication and reports process level details (CPU, memory,
	// goroutine and connection counts), so only enable it on a listener that
	// is not publicly reachable.
	EnableMetrics bool
}

// GetFiberApp returns a Fiber app with the metrics dashboard enabled.
func GetFiberApp(appName string) *fiber.App {
	return GetFiberAppWithOptions(Options{AppName: appName, EnableMetrics: true})
}

// GetFiberAppWithOptions returns a Fiber app configured by opts.
func GetFiberAppWithOptions(opts Options) (app *fiber.App) {
	appName := opts.AppName
	app = fiber.New(fiber.Config{
		// app name
		AppName: appName,
		// When set to true, this will spawn multiple Go processes listening on the same port.
		Prefork: false,
		// Enables the "Server: value" HTTP header.
		ServerHeader: appName,
		// When set to true, the router treats "/foo" and "/foo/" as different.
		StrictRouting: false,
		// When set to true, enables case sensitive routing.
		CaseSensitive: false,
		// The amount of time allowed to read the full request including body.
		ReadTimeout: time.Second * 3,
		// // The maximum amount of time to wait for the next request when keep-alive is enabled.
		IdleTimeout: time.Second * 20,
		// When set to true, it will not print out the «Fiber» ASCII art and listening address.
		DisableStartupMessage: true,
		// If set to true, will print all routes with their method, path and handler.
		EnablePrintRoutes: false,

		//EnableTrustedProxyCheck: true,
		ProxyHeader: "X-Forwarded-For",
		//TrustedProxies:          []string{"127.0.0.1", "10.0.0.0"},
	})

	// inject some middleware we like
	addFiberMiddlewareRecover(app)
	addFiberMiddlewareLogger(app)
	addFiberMiddlewareRequestID(app)
	addFiberMiddlewareCompression(app)
	addFiberMiddlewareEtag(app)
	if opts.EnableMetrics {
		addFiberMiddlewareMetrics(app)
	}
	addFiberMiddlewareFavicon(app)

	return app
}

// Recover from panics
func addFiberMiddlewareRecover(app *fiber.App) {
	app.Use(recover.New())
}

// tweak the logging format
func addFiberMiddlewareLogger(app *fiber.App) {
	app.Use(logger.New(logger.Config{
		// '$remote_host - $header.X-Forwarded-For - $request_host - $header.X-Fabio-Request-Id - [$time_common] "$request" $response_status $response_body_size $response_time_ms "$header.Referer" "$header.User-Agent" upstream "$upstream_addr" "$upstream_service"'
		Format: "accessLog: ${host} - ${respHeader:X-CloudOps-Request-Id} - [${time}] ${method} ${path} ${status} ${bytesSent} ${latency} \"${ua}\"\n",
	}))
}

// Adds an identifier to the response in the header defined below
func addFiberMiddlewareRequestID(app *fiber.App) {
	app.Use(requestid.New(requestid.Config{
		Header: "X-CloudOps-Request-Id",
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

// Adds an endpoint (/metrics) that reports server metrics
func addFiberMiddlewareMetrics(app *fiber.App) {
	app.Get("/metrics", monitor.New(monitor.Config{Title: fmt.Sprintf("%s Metrics UI", app.Config().AppName)}))
}

// Ignores favicon requests or caches a provided icon in memory to improve performance by skipping disk access
func addFiberMiddlewareFavicon(app *fiber.App) {
	app.Use(favicon.New())
}
