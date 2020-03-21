package main

import (
	"strings"

	"github.com/gbolo/protego/config"
	"github.com/gbolo/protego/dataprovider"
	"github.com/gbolo/protego/server"
	"github.com/spf13/viper"
	_ "github.com/gbolo/protego/docs"
)

var log = config.GetLogger()


func main() {
	// init the config
	config.ConfigInit("./testdata/sampleconfig/protego.yaml", true)

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

	// init the server
	err = server.InitServer(p)
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
