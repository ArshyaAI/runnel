package codex

import "testing"

func validArgv() ([]string, []string, []string) {
	node := "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node"
	worker := "/synthetic/tmp/job/trusted-worker.js"
	cwd := "/synthetic/work"
	leaf := []string{node, "--experimental-vm-modules", worker, cwd}
	parent := []string{
		"/Applications/ChatGPT.app/Contents/Resources/codex",
		"sandbox", "--mode", "seatbelt", "--",
		node, "--experimental-vm-modules", worker, cwd,
	}
	return leaf, parent, []string{"/synthetic/tmp"}
}

func TestNormalizeProcessGrammarExact(t *testing.T) {
	leaf, parent, roots := validArgv()
	got, err := NormalizeProcessGrammar(leaf, parent, roots)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodePath != leaf[0] || got.WorkerPath != leaf[2] || got.CWD != leaf[3] || got.CodexPath != parent[0] {
		t.Fatal("normalized grammar did not preserve exact correlation values")
	}
}

func TestNormalizeProcessGrammarRejectsEveryNearMiss(t *testing.T) {
	tests := []struct {
		name string
		edit func(*[]string, *[]string, *[]string)
	}{
		{"leaf extra argument", func(l, _, _ *[]string) { *l = append(*l, "extra") }},
		{"wrong node flag", func(l, _, _ *[]string) { (*l)[1] = "--experimental-vm-module" }},
		{"node outside bundle", func(l, p, _ *[]string) { (*l)[0] = "/usr/bin/node"; (*p)[5] = "/usr/bin/node" }},
		{"worker outside bounded root", func(l, p, _ *[]string) { (*l)[2] = "/other/trusted-worker.js"; (*p)[7] = (*l)[2] }},
		{"worker traversal", func(l, p, _ *[]string) { (*l)[2] = "/synthetic/tmp/../trusted-worker.js"; (*p)[7] = (*l)[2] }},
		{"relative cwd", func(l, p, _ *[]string) { (*l)[3] = "relative"; (*p)[8] = "relative" }},
		{"wrong parent command", func(_, p, _ *[]string) { (*p)[1] = "exec" }},
		{"parent suffix mismatch", func(_, p, _ *[]string) { (*p)[8] = "/synthetic/other" }},
		{"missing separator", func(_, p, _ *[]string) { (*p)[4] = "not-separator" }},
		{"duplicate separator", func(_, p, _ *[]string) { (*p)[2] = "--" }},
		{"wrong parent executable", func(_, p, _ *[]string) { (*p)[0] = "/Applications/ChatGPT.app/Contents/Resources/not-codex" }},
		{"empty temp roots", func(_, _, r *[]string) { *r = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leaf, parent, roots := validArgv()
			test.edit(&leaf, &parent, &roots)
			if _, err := NormalizeProcessGrammar(leaf, parent, roots); err == nil {
				t.Fatal("near miss accepted")
			}
		})
	}
}
