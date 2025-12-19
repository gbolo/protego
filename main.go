package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	_ "github.com/gbolo/protego/docs"
	"github.com/gbolo/protego/internal/config"
	"github.com/gbolo/protego/internal/meta"
	"github.com/gbolo/protego/internal/server"
	"github.com/gbolo/protego/pkg/dataprovider"
	"github.com/spf13/viper"
)

var (
	configFile  = flag.String("config", "", "Path to config file (optional, will use defaults if not specified)")
	showVersion = flag.Bool("version", false, "Show version information and exit")
)

var log = config.GetLogger()

func main() {
	flag.Parse()

	// Handle version flag
	if *showVersion {
		fmt.Println(meta.GetAppMetadata("protego").ToString())
		os.Exit(0)
	}

	log.Infof("initializing -- %s", meta.GetAppMetadata("protego").ToString())

	// init the config
	config.ConfigInit(*configFile, true)

	// init the data provider
	var p dataprovider.Provider
	var err error
	switch provider := strings.ToLower(viper.GetString("db.provider")); provider {
	case "bolt":
		bolt, e := dataprovider.NewBoltProvider()
		p = &bolt
		err = e
	case "memory":
		memory, e := dataprovider.NewMemoryProvider()
		p = &memory
		err = e
	default:
		log.Fatalf("the value set for db.provider is unrecognized: %s", provider)
	}
	if err != nil {
		log.Fatalf("failed to init data provider: %v", err)
	}

	// init the fiber server
	err = server.InitFiberServer(p)
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
