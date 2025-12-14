package log

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Defaults
var (
	Base       = zap.NewNop()
	Logger     = Base.Sugar()
	funcLogger = Base.WithOptions(zap.AddCallerSkip(1)).Sugar()
)

type LoggerConfig struct {
	Level             string `json:"level"`
	Encoding          string `json:"encoding"`
	DevMode           bool   `json:"dev_mode"`
	EnableColor       bool   `json:"enable_color"`
	DisableSampling   bool   `json:"disable_sampling"`
	DisableCaller     bool   `json:"disable_caller"`
	DisableStacktrace bool   `json:"disable_stacktrace"`
}

// MustInitDefaultLogger loads a global logger based on predefined defaults
func MustInitDefaultLogger() {
	if err := InitLogger(GetDefaultLoggerConfig()); err != nil {
		fmt.Printf("could not configure logger: %v", err)
		os.Exit(1)
	}
}

func GetDefaultLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		Level:             "debug",
		Encoding:          "console",
		EnableColor:       true,
		DevMode:           false,
		DisableCaller:     false,
		DisableStacktrace: true,
	}
}

// InitLogger loads a global logger based on a configuration
func InitLogger(c *LoggerConfig) error {
	if c == nil {
		return fmt.Errorf("LoggerConfig cannot be nil")
	}

	logConfig := zap.NewProductionConfig()
	if c.DisableSampling {
		logConfig.Sampling = nil
	}

	// Log Level
	var logLevel zapcore.Level
	if err := logLevel.Set(c.Level); err != nil {
		return fmt.Errorf("could not determine log level: %w", err)
	}
	logConfig.Level.SetLevel(logLevel)

	// Handle different logger encodings
	switch c.Encoding {
	default:
		logConfig.Encoding = c.Encoding
		// Enable color ONLY when in console
		if c.EnableColor && logConfig.Encoding == "console" {
			logConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}
		logConfig.DisableStacktrace = c.DisableStacktrace
		// Use sane timestamp when logging to console
		if logConfig.Encoding == "console" {
			logConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		}

		// JSON Fields
		logConfig.EncoderConfig.MessageKey = "msg"
		logConfig.EncoderConfig.LevelKey = "level"
		logConfig.EncoderConfig.CallerKey = "caller"
		logConfig.EncoderConfig.ConsoleSeparator = " "
		logConfig.EncoderConfig.NameKey = "app"

	}

	// Settings
	logConfig.Development = c.DevMode
	logConfig.DisableCaller = c.DisableCaller

	// Build the logger
	globalLogger, err := logConfig.Build()
	if err != nil {
		return fmt.Errorf("could not build log config: %w", err)
	}

	// Enforce stack traces for fatal level even when stack traces are disabled
	if logConfig.DisableStacktrace {
		globalLogger = globalLogger.WithOptions(zap.AddStacktrace(zap.FatalLevel))
	}

	zap.ReplaceGlobals(globalLogger)

	Base = zap.L()
	Logger = Base.Sugar()
	funcLogger = Base.WithOptions(zap.AddCallerSkip(1)).Sugar()

	Debugw("initialized logger", "logger_config", c)
	return nil
}

// MustInitLogger will produce a fatal error if it cannot load the config
func MustInitLogger(c *LoggerConfig) {
	if err := InitLogger(c); err != nil {
		fmt.Printf("could not init logger: %v\n", err)
		os.Exit(1)
	}
}
