package config

import (
	"strings"

	"github.com/spf13/viper"
)

const (
	AppName = "protego"
)

var (
	EnvConfigPrefix = strings.ToLower(AppName)
)

// ConfigInit instantiates and validates the configuration options
// optionally it can print out a configuration summary
func ConfigInit(cfgFile string, printConfig bool) {
	// init viper
	initViper(cfgFile)

	// Print config if required
	if printConfig {
		printConfigSummary()
	}

	// Sanity checks
	sanityChecks()

	// assign variable values to config values...
}

// setup viper
func initViper(cfgFile string) {
	// Set some defaults
	viper.SetDefault("log_level", "DEBUG")
	viper.SetDefault("server.bind_address", "127.0.0.1")
	viper.SetDefault("server.bind_port", "8080")
	viper.SetDefault("server.access_log", true)
	viper.SetDefault("db.provider", "bolt")
	// the admin listener defaults to loopback only: it serves the admin API,
	// the admin UI, swagger and metrics, none of which should face the internet
	viper.SetDefault("admin.bind_address", "127.0.0.1")
	viper.SetDefault("admin.bind_port", "8081")

	// Configuring and pulling overrides from environmental variables
	viper.SetEnvPrefix(EnvConfigPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// set default config name and paths to look for it
	viper.SetConfigType("yaml")
	viper.SetConfigName(AppName)
	viper.AddConfigPath("/etc/protego")
	viper.AddConfigPath("./testdata/sampleconfig")

	// if the user provides a config file in a flag, lets use it
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}

	// If a config file is found, read it in.
	err := viper.ReadInConfig()

	// Kick-off the logging module
	loggingInit(viper.GetString("log_level"))

	if err == nil {
		log.Infof("using config file: %s", viper.ConfigFileUsed())
	} else {
		log.Warningf("no config file found: using environment variables and hard-coded defaults: %v", err)
	}
}

// prints the config options
func printConfigSummary() {
	log.Debugf("Configuration:\n")
	for _, c := range []string{
		"log_level",
		"server.bind_address",
		"server.bind_port",
		"admin.bind_address",
		"admin.bind_port",
		"server.tls.enabled",
		"server.access_log",
		"server.compression",
		"db.provider",
		"db.bolt.file",
	} {
		log.Debugf("%s: %s\n", c, viper.GetString(c))
	}
}

// checks that the config is correctly defined
func sanityChecks() {
	// the public and admin listeners cannot share a port. Fail here rather than
	// let the second listener die with a bind error that says nothing about
	// which config option is wrong.
	if viper.GetString("server.bind_port") == viper.GetString("admin.bind_port") {
		log.Fatalf(
			"server.bind_port and admin.bind_port must differ, both are set to %s",
			viper.GetString("server.bind_port"),
		)
	}

	// warn loudly if the admin listener is not restricted to a single interface
	switch viper.GetString("admin.bind_address") {
	case "0.0.0.0", "::", "":
		log.Warning("admin.bind_address is not restricted to a single interface: the admin API, admin UI, " +
			"swagger docs and metrics dashboard may be reachable from untrusted networks")
	}

	maxTTl := viper.GetInt("ttl.max")
	switch {
	case maxTTl < 0:
		log.Fatal("ttl.max must be greater or equal to 0")
	case maxTTl == 0:
		log.Warning("ttl.max is set to 0 which allows for unlimited TTLs!")
	case maxTTl > 60*24*90:
		log.Warning("ttl.max is set to a value longer than 90 days: %d mins", maxTTl)
	}
}
