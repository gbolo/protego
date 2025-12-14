package config

import (
	"github.com/spf13/viper"
	"strings"
)

const (
	AppName         = "protego"
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

	return
}

// setup viper
func initViper(cfgFile string) {

	// Set some defaults
	viper.SetDefault("log_level", "DEBUG")
	viper.SetDefault("server.bind_address", "127.0.0.1")
	viper.SetDefault("server.bind_port", "8080")
	viper.SetDefault("server.access_log", true)
	viper.SetDefault("db.provider", "bolt")

	// Configuring and pulling overrides from environmental variables
	viper.SetEnvPrefix(EnvConfigPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// set default config name and paths to look for it
	viper.SetConfigType("yaml")
	viper.SetConfigName(AppName)
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

	// check stuff here
}
