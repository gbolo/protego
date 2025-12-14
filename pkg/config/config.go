package config

const (
	AppName = "protego"
)

// ConfigInit instantiates and validates the configuration options
// This is a wrapper to maintain backward compatibility
func ConfigInit(cfgFile string, printConfig bool) {
	// Initialize viper and logger
	MustInitViperAndLogger(AppName, cfgFile)

	// Print config if required
	if printConfig {
		PrintConfigSummary()
	}

	// Sanity checks
	sanityChecks()
}

// checks that the config is correctly defined
func sanityChecks() {
	// check stuff here
}
