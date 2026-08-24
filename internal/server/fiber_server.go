package server

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/gbolo/protego/internal/config"
	"github.com/gbolo/protego/pkg/dataprovider"
	"github.com/gbolo/protego/pkg/fiberapp"
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
)

var (
	log          = config.GetLogger()
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

// InitFiberServer initializes the Fiber-based HTTP server
func InitFiberServer(p dataprovider.Provider) error {
	if p == nil {
		return fmt.Errorf("data provider is nil")
	}
	if err := p.CheckAvailability(); err != nil {
		return err
	}
	// set the data provider
	dataProvider = p
	// set the dynamic dns provider (pass data provider reference for syncing)
	ddnsProvider = dataprovider.NewDdnsProvider(dataProvider)
	// sync all existing users from dataprovider into ddnsprovider
	if err := ddnsProvider.SyncAllUsers(); err != nil {
		return err
	}
	// start fiber http server
	return startFiberServer()
}

// startFiberServer starts the two HTTP listeners:
//
//	public -- the challenge UI and the challenge endpoint only
//	admin  -- the admin API and UI, swagger docs, metrics and forward-auth
//
// Only the public listener is meant to be reachable from the internet. The
// process exits as soon as either listener fails.
func startFiberServer() error {
	// the public listener gets no metrics dashboard: it is unauthenticated
	publicApp := fiberapp.GetFiberAppWithOptions(fiberapp.Options{
		AppName:       "Protego",
		EnableMetrics: false,
	})
	setupPublicRoutes(publicApp)

	adminApp := fiberapp.GetFiberAppWithOptions(fiberapp.Options{
		AppName:       "Protego Admin",
		EnableMetrics: true,
	})
	setupAdminRoutes(adminApp)

	publicAddress := net.JoinHostPort(
		viper.GetString("server.bind_address"),
		viper.GetString("server.bind_port"),
	)
	adminAddress := net.JoinHostPort(
		viper.GetString("admin.bind_address"),
		viper.GetString("admin.bind_port"),
	)

	// validate the TLS material once, before either listener starts
	tlsEnabled := viper.GetBool("server.tls.enabled")
	if tlsEnabled {
		if _, err := configureFiberTLS(); err != nil {
			log.Fatalf("error configuring TLS: %s", err)
			return err
		}
		log.Infof("TLS enabled")
	}

	listen := func(name, address string, app *fiber.App) error {
		log.Infof("starting %s HTTP server: listening on %s", name, address)
		if tlsEnabled {
			return app.ListenTLS(
				address,
				viper.GetString("server.tls.cert_chain"),
				viper.GetString("server.tls.private_key"),
			)
		}
		return app.Listen(address)
	}

	// buffered so the goroutine that loses the race can still exit
	errChan := make(chan error, 2)
	go func() {
		errChan <- listen("admin", adminAddress, adminApp)
	}()
	go func() {
		errChan <- listen("public", publicAddress, publicApp)
	}()

	// either listener going down takes the process with it
	return <-errChan
}

// configureFiberTLS configures TLS settings for Fiber
func configureFiberTLS() (*tls.Config, error) {
	if !viper.GetBool("server.tls.enabled") {
		log.Debug("TLS not enabled, skipping TLS config")
		return nil, nil
	}

	// attempt to load configured cert/key
	log.Info("TLS enabled, loading cert and key")
	log.Debugf("loading TLS cert and key: %s %s", viper.GetString("server.tls.cert_chain"), viper.GetString("server.tls.private_key"))
	cert, err := tls.LoadX509KeyPair(viper.GetString("server.tls.cert_chain"), viper.GetString("server.tls.private_key"))
	if err != nil {
		return nil, err
	}

	// configure hardened TLS settings
	//nolint:gosec // G402: TLS 1.2 is acceptable minimum version
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tlsMinVersion,
		InsecureSkipVerify: false,
		CurvePreferences:   tlsCurvePreferences,
		CipherSuites:       tlsCiphers,
	}

	return tlsConfig, nil
}
