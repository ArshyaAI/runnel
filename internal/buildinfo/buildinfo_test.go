package buildinfo

import (
	"encoding/json"
	"testing"
)

func TestCurrentAndJSON(t *testing.T) {
	oldVersion, oldCommit, oldDate := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = oldVersion, oldCommit, oldDate })
	Version, Commit, Date = "", "", ""
	info := Current()
	if info.Version != "dev" || info.Commit != "unknown" || info.BuildDate != "unknown" || info.OS == "" || info.Arch == "" || info.GoVersion == "" {
		t.Fatalf("unexpected info: %#v", info)
	}
	data, err := info.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["version"] != "dev" || len(decoded) != 6 {
		t.Fatalf("unexpected JSON: %s", data)
	}
}
