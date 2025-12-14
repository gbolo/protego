package config

import (
	"github.com/gbolo/protego/pkg/log"
	stdlog "log"
	"strings"

	"github.com/spf13/viper"
)

// MustInitViper initializes viper or dies.
// appName is used for env prefix (it gets capitalized) and also for default config name: <appName>-config.
// if cfgFile is specified, it will attempt to load it or die.
func MustInitViper(appName, cfgFile string) {

	// Configuring and pulling overrides from environmental variables
	viper.SetEnvPrefix(strings.ToUpper(strings.Replace(appName, "-", "", -1)))
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// set default config name and paths to look for it
	viper.SetConfigType("yaml")
	viper.SetConfigName(appName)
	viper.AddConfigPath("./")
	viper.AddConfigPath("./testdata/sampleconfig")
	viper.AddConfigPath("/etc/protego")

	// Set some defaults
	viper.SetDefault("log.level", "debug")
	viper.SetDefault("log.encoding", "console")
	viper.SetDefault("log.enable_color", true)
	viper.SetDefault("server.bind_address", "127.0.0.1")
	viper.SetDefault("server.bind_port", "8080")
	viper.SetDefault("server.access_log", true)
	viper.SetDefault("db.provider", "bolt")

	// if the user provides a config file in a flag, lets use it
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}

	// If a config file is found, read it in.
	errConfigLoad := viper.ReadInConfig()

	// configuration file is optional, but fatal error if we can't load specified config
	if _, ok := errConfigLoad.(viper.ConfigFileNotFoundError); !ok && errConfigLoad != nil {
		// the real logger has not be initialized yet. so just use log pkg from std lib for now...
		stdlog.Fatalf("unable to load configuration file: %v", errConfigLoad)
	}
}

// MustInitViperAndLogger initializes both viper and our pkg/log or dies.
// If the logger config is empty, it will generate a default logging config
func MustInitViperAndLogger(appName, cfgFile string) {
	MustInitViper(appName, cfgFile)
	initLoggerFallbackToDefault()

	// at this point our logger is ready, so we can start printing nice log messages! ;)
	if viper.ConfigFileUsed() == "" {
		log.Infof("not using a config file")
	} else {
		log.Infof("using config file: %s", viper.ConfigFileUsed())
	}
}

func initLoggerFallbackToDefault() (logConfig *log.LoggerConfig) {
	logConfig = GetLoggerConfigFromViper()
	err := log.InitLogger(logConfig)
	if err != nil {
		logConfig = log.GetDefaultLoggerConfig()
		log.MustInitLogger(logConfig)
		log.Warnf("used default logger config due to error with provided config: %v", err)
	}
	return
}

// GetLoggerConfigFromViper starts with default logging config and overrides the fields from viper.
// since viper.UnmarshalKey does not get overrides from env vars, this function is more involved ;(
func GetLoggerConfigFromViper() (c *log.LoggerConfig) {
	c = log.GetDefaultLoggerConfig()
	stringKeys := map[string]*string{
		"log.level":    &c.Level,
		"log.encoding": &c.Encoding,
	}
	boolKeys := map[string]*bool{
		"log.dev_mode":           &c.DevMode,
		"log.disable_sampling":   &c.DisableSampling,
		"log.disable_caller":     &c.DisableCaller,
		"log.disable_stacktrace": &c.DisableStacktrace,
		"log.enable_color":       &c.EnableColor,
	}
	for k, v := range stringKeys {
		if viper.IsSet(k) {
			*v = viper.GetString(k)
		}
	}
	for k, v := range boolKeys {
		if viper.IsSet(k) {
			*v = viper.GetBool(k)
		}
	}
	return
}

// PrintConfigSummary prints the configuration summary
func PrintConfigSummary() {
	log.Debugf("Configuration:")
	for _, c := range []string{
		"log.level",
		"log.encoding",
		"server.bind_address",
		"server.bind_port",
		"server.tls.enabled",
		"server.access_log",
		"server.compression",
		"db.provider",
		"db.bolt.file",
	} {
		log.Debugf("  %s: %s", c, viper.GetString(c))
	}
}
