package main

import (
	"strings"

	_ "github.com/gbolo/protego/docs"
	"github.com/gbolo/protego/internal/config"
	"github.com/gbolo/protego/internal/meta"
	"github.com/gbolo/protego/internal/server"
	"github.com/gbolo/protego/pkg/dataprovider"
	"github.com/spf13/viper"
)

var log = config.GetLogger()

func main() {
	log.Infof("initializing -- %s", meta.GetAppMetadata("protego").ToString())

	// init the config
	config.ConfigInit("", true)

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
