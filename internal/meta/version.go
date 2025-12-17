package meta

import (
	"fmt"
	"runtime"
)

var (

	// !! The variables below should be injected via LD flags
	// !! DO NOT CHANGE THESE DEFAULT VALUES !!

	// Version of application
	Version = "devel"
	// CommitSHA is the short SHA hash of the git commit
	CommitSHA = "unknown"
	// BuildDate is the date this application was compiled
	BuildDate = "unknown"
)

type appMetadata struct {
	AppName    string `json:"app_name"`
	AppVersion string `json:"app_version"`
	CommitRef  string `json:"commit_ref"`
	GoVersion  string `json:"go_version"`
	GoPlatform string `json:"go_platform"`
}

// PrintVersion prints the current version information to stdout
func PrintVersion() {
	fmt.Printf(`metadata:
  version     : %s
  build date  : %s
  git hash    : %s
  go version  : %s
  go compiler : %s
  platform    : %s/%s
`, Version, BuildDate, CommitSHA, runtime.Version(), runtime.Compiler, runtime.GOOS, runtime.GOARCH)
}

func GetAppMetadata(appName string) appMetadata {
	info := appMetadata{
		AppName:    appName,
		AppVersion: Version,
		CommitRef:  CommitSHA,
		GoVersion:  runtime.Version(),
		GoPlatform: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
	if info.CommitRef == "" {
		info.CommitRef = "unknown"
	}
	if info.AppVersion == "" {
		info.AppVersion = "devel"
	}
	return info
}

func (i appMetadata) ToString() string {
	return fmt.Sprintf("%s version: %s (ref-%s), platform: %s [%s]", i.AppName, i.AppVersion, i.CommitRef, i.GoVersion, i.GoPlatform)
}
