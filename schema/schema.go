// Package schema embeds and compiles Runnel's closed Draft 2020-12 schemas.
package schema

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

type Name string

const (
	Snapshot        Name = "snapshot-v1.schema.json"
	ShareSnapshot   Name = "share-snapshot-v1.schema.json"
	PreparedReceipt Name = "prepared-receipt-v1.schema.json"
	ResultReceipt   Name = "result-receipt-v1.schema.json"
	ShareReceipt    Name = "share-receipt-v1.schema.json"
	CodexFixture    Name = "codex-fixture-v1.schema.json"
	CodexManifest   Name = "codex-fixture-manifest-v1.schema.json"
)

const common = "common-v1.schema.json"

var orderedNames = []Name{Snapshot, ShareSnapshot, PreparedReceipt, ResultReceipt, ShareReceipt, CodexFixture, CodexManifest}

var resourceIDs = map[string]string{
	common:                  "https://schemas.runnel.dev/v1/common.json",
	string(Snapshot):        "https://schemas.runnel.dev/v1/snapshot.json",
	string(ShareSnapshot):   "https://schemas.runnel.dev/v1/share-snapshot.json",
	string(PreparedReceipt): "https://schemas.runnel.dev/v1/prepared-receipt.json",
	string(ResultReceipt):   "https://schemas.runnel.dev/v1/result-receipt.json",
	string(ShareReceipt):    "https://schemas.runnel.dev/v1/share-receipt.json",
	string(CodexFixture):    "https://schemas.runnel.dev/v1/codex-fixture.json",
	string(CodexManifest):   "https://schemas.runnel.dev/v1/codex-fixture-manifest.json",
}

//go:embed *.schema.json
var files embed.FS

var compiled struct {
	sync.Once
	values map[Name]*jsonschema.Schema
	err    error
}

func Names() []Name { return append([]Name(nil), orderedNames...) }

func Bytes(name Name) ([]byte, error) {
	if _, ok := resourceIDs[string(name)]; !ok || name == Name(common) {
		return nil, fmt.Errorf("schema: unknown public schema %q", name)
	}
	data, err := files.ReadFile(string(name))
	if err != nil {
		return nil, fmt.Errorf("schema: read %s: %w", name, err)
	}
	return append([]byte(nil), data...), nil
}

func Compile(name Name) (*jsonschema.Schema, error) {
	compileOnce()
	if compiled.err != nil {
		return nil, compiled.err
	}
	value, ok := compiled.values[name]
	if !ok {
		return nil, fmt.Errorf("schema: unknown schema %q", name)
	}
	return value, nil
}

func CompileAll() error { compileOnce(); return compiled.err }

func Validate(name Name, data []byte) error {
	sch, err := Compile(name)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("schema: decode instance: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("schema: trailing JSON document")
		}
		return fmt.Errorf("schema: trailing JSON: %w", err)
	}
	if err := sch.Validate(value); err != nil {
		return fmt.Errorf("schema: validate %s: %w", name, err)
	}
	return nil
}

func compileOnce() {
	compiled.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		for _, filename := range append([]string{common}, namesAsStrings()...) {
			data, err := files.ReadFile(filename)
			if err != nil {
				compiled.err = fmt.Errorf("schema: read %s: %w", filename, err)
				return
			}
			var document any
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.UseNumber()
			if err := decoder.Decode(&document); err != nil {
				compiled.err = fmt.Errorf("schema: decode %s: %w", filename, err)
				return
			}
			if err := compiler.AddResource(resourceIDs[filename], document); err != nil {
				compiled.err = fmt.Errorf("schema: add %s: %w", filename, err)
				return
			}
		}
		compiled.values = make(map[Name]*jsonschema.Schema, len(orderedNames))
		for _, name := range orderedNames {
			sch, err := compiler.Compile(resourceIDs[string(name)])
			if err != nil {
				compiled.err = fmt.Errorf("schema: compile %s: %w", name, err)
				return
			}
			compiled.values[name] = sch
		}
	})
}

func namesAsStrings() []string {
	result := make([]string, len(orderedNames))
	for i, name := range orderedNames {
		result[i] = string(name)
	}
	return result
}
