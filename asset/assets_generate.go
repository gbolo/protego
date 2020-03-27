// +build ignore

// this main needs to run every time the physical assets on disk change
package main

import (
	"net/http"
	"time"

	"github.com/gbolo/protego/config"
	"github.com/prometheus/alertmanager/pkg/modtimevfs"
	"github.com/shurcooL/vfsgen"
)

var log = config.GetLogger()

func main() {
	// ensure that timestamps of files never change so that `vfsgen` generate becomes deterministic
	fs := modtimevfs.New(http.Dir("../embedded"), time.Unix(1, 0))
	err := vfsgen.Generate(fs, vfsgen.Options{
		PackageName:  "asset",
		BuildTags:    "!dev",
		VariableName: "Assets",
	})
	if err != nil {
		log.Fatal(err)
	}
}
