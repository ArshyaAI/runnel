package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArshyaAI/runnel/internal/cli"
)

func TestProductionDefaultScanDoesNotCreateReceiptStore(t *testing.T) {
	base, err := os.MkdirTemp("/private/tmp", "runnel-main-scan-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUNNEL_DATA_HOME", base)
	receipts := filepath.Join(base, "receipts")
	var output bytes.Buffer
	command := cli.NewRoot(productionOptions())
	command.SetIn(&bytes.Buffer{})
	command.SetOut(&output)
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"scan", "--json"})
	err = command.Execute()
	if err != nil {
		var exit *cli.ExitError
		if !errors.As(err, &exit) || exit.Code != cli.ExitPartial {
			t.Fatalf("scan error = %v", err)
		}
	}
	if _, err := os.Stat(receipts); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("default scan created receipt store: %v", err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"schema_version":"runnel.snapshot/v1"`)) {
		t.Fatalf("scan output is not a snapshot: %s", output.Bytes())
	}
}
