package server

import (
	"crypto/tls"
	"fmt"

	"github.com/gbolo/protego/config"
	"github.com/gbolo/protego/dataprovider"
	"github.com/gbolo/protego/pkg/fiberapp"
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
	// set the dynamic dns provider
	ddnsProvider = dataprovider.NewDdnsProvider()
	// populate any existing users from dataprovider into ddnsprovider
	users, err := dataProvider.GetAllUsers()
	if err != nil {
		return err
	}
	ddnsProvider.ProcessUsers(users)
	// start fiber http server
	return startFiberServer()
}

func startFiberServer() error {
	// Create Fiber app
	app := fiberapp.GetFiberApp("Protego")

	// Setup routes
	setupFiberRoutes(app)

	// Get server config
	address := fmt.Sprintf(
		"%s:%s",
		viper.GetString("server.bind_address"),
		viper.GetString("server.bind_port"),
	)

	log.Infof("starting Fiber HTTP server: listening on %s", address)

	// Start with or without TLS
	if viper.GetBool("server.tls.enabled") {
		_, err := configureFiberTLS()
		if err != nil {
			log.Fatalf("error configuring TLS: %s", err)
			return err
		}

		log.Infof("TLS enabled")
		return app.ListenTLS(address, viper.GetString("server.tls.cert_chain"), viper.GetString("server.tls.private_key"))
	}

	return app.Listen(address)
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
	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tlsMinVersion,
		InsecureSkipVerify:       false,
		PreferServerCipherSuites: true,
		CurvePreferences:         tlsCurvePreferences,
		CipherSuites:             tlsCiphers,
	}

	return tlsConfig, nil
}

