//go:build go1.8
// +build go1.8

// enforce go 1.8+ just so we can support X25519 curve :)

package server

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/gbolo/protego/pkg/asset"
	"github.com/gbolo/protego/pkg/config"
	"github.com/gbolo/protego/pkg/dataprovider"
	"github.com/gbolo/protego/pkg/httpserver"
	"github.com/gbolo/protego/pkg/log"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	httpSwagger "github.com/gofiber/swagger"
	"github.com/spf13/viper"
)

var (
	dataProvider dataprovider.Provider
	ddnsProvider dataprovider.DdnsProvider

	// PCI compliance as of Jun 30, 2018: anything under TLS 1.1 must be disabled
	// we bump this up to TLS 1.2 so we can support best possible ciphers
	tlsMinVersion = uint16(tls.VersionTLS12)
	// allowed ciphers when in hardened mode
	// disable CBC suites (Lucky13 attack) this means TLS 1.1 can't work (no GCM)
	// only use perfect forward secrecy ciphers
	tlsCiphers = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		// these ciphers require go 1.8+
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	// EC curve preference when in hardened mode
	// curve reference: http://safecurves.cr.yp.to/
	tlsCurvePreferences = []tls.CurveID{
		// this curve is a non-NIST curve with no NSA influence. Prefer this over all others!
		// this curve required go 1.8+
		tls.X25519,
		// These curves are provided by NIST; prefer in descending order
		tls.CurveP521,
		tls.CurveP384,
		tls.CurveP256,
	}
)

func InitServer(p dataprovider.Provider) error {
	if p == nil {
		return fmt.Errorf("data provider is nil")
	}
	if err := p.CheckAvailability(); err != nil {
		return err
	}
	// set the data provider
	dataProvider = p
	// set the dynamic dns provider
	ddnsProvider = dataprovider.NewDdnsProvider()
	// populate any existing users from dataprovider into ddnsprovider
	users, err := dataProvider.GetAllUsers()
	if err != nil {
		return err
	}
	ddnsProvider.ProcessUsers(users)
	// start http server
	return startHTTPServer()
}

// setupRoutes configures all the API routes and middleware
func setupRoutes(app *fiber.App) {
	// API routes with versioning
	api := app.Group("/api/v1")

	// Version endpoint
	api.Get("/version", handlerVersion)

	// Authorization endpoints
	api.Get("/authorize", handlerAuthorize)
	api.Post("/challenge", handlerChallenge)

	// User management endpoints
	api.Post("/user", handlerUserAdd)
	api.Put("/user/:user-id", handlerUserUpdate)
	api.Get("/user/:user-id", handlerUserGet)
	api.Get("/user", handlerUserGetAll)
	api.Delete("/user/:user-id", handlerUserDelete)

	// Swagger UI
	app.Get("/swagger", func(c *fiber.Ctx) error {
		return c.Redirect("/swagger/index.html", fiber.StatusMovedPermanently)
	})
	app.Get("/swagger/*", httpSwagger.HandlerDefault)

	// Serve embedded static assets (web UI)
	// Use adaptor to convert http.FileServer to Fiber handler
	fileServer := http.FileServer(asset.Assets)
	app.Get("/*", adaptor.HTTPHandler(fileServer))
}

func startHTTPServer() (err error) {
	// create fiber app with configuration
	app := httpserver.GetFiberApp(
		config.AppName,
		viper.GetBool("server.access_log"),
		viper.GetBool("server.compression"),
		viper.GetBool("server.enable_profiler"),
	)

	// setup routes
	setupRoutes(app)

	// get listen address
	address := fmt.Sprintf(
		"%s:%s",
		viper.GetString("server.bind_address"),
		viper.GetString("server.bind_port"),
	)

	// start the server
	if viper.GetBool("server.tls.enabled") {
		// get TLS config
		tlsConfig, err := configureTLS()
		if err != nil {
			log.Fatalf("error configuring TLS: %s", err)
			return err
		}

		log.Infof("starting HTTP server with TLS enabled: listening on %s", address)
		err = app.ListenTLSWithCertificate(address, tls.Certificate{})
		// Use custom listener with TLS config
		ln, lnErr := tls.Listen("tcp", address, &tlsConfig)
		if lnErr != nil {
			log.Fatalf("failed to create TLS listener: %s", lnErr)
			return lnErr
		}
		err = app.Listener(ln)
	} else {
		log.Infof("starting HTTP server: listening on %s", address)
		err = app.Listen(address)
	}

	if err != nil {
		log.Fatalf("failed to start server: %s", err)
	}

	return
}

// configure TLS as defined in configuration
func configureTLS() (tlsConfig tls.Config, err error) {

	if !viper.GetBool("server.tls.enabled") {
		log.Debug("TLS not enabled, skipping TLS config")
		return
	}

	// attempt to load configured cert/key
	log.Info("TLS enabled, loading cert and key")
	log.Debugf("loading TLS cert and key: %s %s", viper.GetString("server.tls.cert_chain"), viper.GetString("server.tls.private_key"))
	cert, err := tls.LoadX509KeyPair(viper.GetString("server.tls.cert_chain"), viper.GetString("server.tls.private_key"))
	if err != nil {
		return
	}

	// configure hardened TLS settings
	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsConfig.MinVersion = tlsMinVersion
	tlsConfig.InsecureSkipVerify = false
	tlsConfig.PreferServerCipherSuites = true
	tlsConfig.CurvePreferences = tlsCurvePreferences
	tlsConfig.CipherSuites = tlsCiphers

	return
}
