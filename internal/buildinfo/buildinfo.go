// Package buildinfo exposes immutable release provenance injected at link time.
package buildinfo

import (
	"encoding/json"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func Current() Info {
	return Info{
		Version:   nonEmpty(Version, "dev"),
		Commit:    nonEmpty(Commit, "unknown"),
		BuildDate: nonEmpty(Date, "unknown"),
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

func (i Info) JSON() ([]byte, error) { return json.Marshal(i) }

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
