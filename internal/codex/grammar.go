package codex

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// ProcessGrammar is private correlation material. Its fields are excluded
// from JSON so it cannot accidentally become public detector output.
type ProcessGrammar struct {
	NodePath   string `json:"-"`
	WorkerPath string `json:"-"`
	CWD        string `json:"-"`
	CodexPath  string `json:"-"`
}

// NormalizeProcessGrammar validates the exact v1 leaf and parent argv forms.
// tempRoots must be explicit absolute roots supplied by the platform probe;
// no environment or live filesystem inference is performed here.
func NormalizeProcessGrammar(leafArgv, parentArgv, tempRoots []string) (ProcessGrammar, error) {
	if len(leafArgv) != 4 || leafArgv[1] != "--experimental-vm-modules" {
		return ProcessGrammar{}, safeError(CodeArgvMismatch)
	}
	nodePath, err := exactAbsolutePath(leafArgv[0])
	if err != nil || !strings.HasSuffix(filepath.ToSlash(nodePath), NodeBundleSuffix) {
		return ProcessGrammar{}, safeError(CodeArgvMismatch)
	}
	workerPath, err := exactAbsolutePath(leafArgv[2])
	if err != nil || filepath.Base(workerPath) != WorkerFilename || !withinAnyRoot(workerPath, tempRoots) {
		return ProcessGrammar{}, safeError(CodeArgvMismatch)
	}
	cwd, err := exactAbsolutePath(leafArgv[3])
	if err != nil {
		return ProcessGrammar{}, safeError(CodeArgvMismatch)
	}

	if len(parentArgv) < len(leafArgv)+3 || parentArgv[1] != "sandbox" {
		return ProcessGrammar{}, safeError(CodeParentMismatch)
	}
	codexPath, err := exactAbsolutePath(parentArgv[0])
	if err != nil || filepath.Base(codexPath) != CodexIdentifier {
		return ProcessGrammar{}, safeError(CodeParentMismatch)
	}
	separator := -1
	for i := 2; i < len(parentArgv); i++ {
		if parentArgv[i] != "--" {
			continue
		}
		if separator != -1 {
			return ProcessGrammar{}, safeError(CodeParentMismatch)
		}
		separator = i
	}
	if separator < 2 || !slices.Equal(parentArgv[separator+1:], leafArgv) {
		return ProcessGrammar{}, safeError(CodeParentMismatch)
	}

	return ProcessGrammar{
		NodePath:   nodePath,
		WorkerPath: workerPath,
		CWD:        cwd,
		CodexPath:  codexPath,
	}, nil
}

func exactAbsolutePath(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", fmt.Errorf("non-canonical path")
	}
	return value, nil
}

func withinAnyRoot(path string, roots []string) bool {
	for _, root := range roots {
		cleanRoot, err := exactAbsolutePath(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(cleanRoot, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return true
	}
	return false
}
