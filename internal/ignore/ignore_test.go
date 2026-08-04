package ignore

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func matcherFrom(t *testing.T, patterns string) *Matcher {
	t.Helper()
	m := &Matcher{}
	if err := m.AddFile(strings.NewReader(patterns), "test"); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBasicSemantics(t *testing.T) {
	cases := []struct {
		patterns string
		path     string
		isDir    bool
		want     bool
	}{
		// unanchored matches at any depth
		{"*.pem", "server.pem", false, true},
		{"*.pem", "certs/server.pem", false, true},
		{"*.pem", "certs/server.pem.txt", false, false},
		// leading slash anchors
		{"/secrets", "secrets", false, true},
		{"/secrets", "sub/secrets", false, false},
		// embedded slash anchors
		{"config/creds.json", "config/creds.json", false, true},
		{"config/creds.json", "x/config/creds.json", false, false},
		// trailing slash: directories only
		{"build/", "build", true, true},
		{"build/", "build", false, false},
		// negation, last match wins
		{"*.env\n!keep.env", "keep.env", false, false},
		{"*.env\n!keep.env", "prod.env", false, true},
		{"!keep.env\n*.env", "keep.env", false, true},
		// parent rule: no re-inclusion under an excluded directory
		{"secret/\n!secret/ok.txt", "secret/ok.txt", false, true},
		// ? does not cross /
		{"a?c", "abc", false, true},
		{"a?c", "a/c", false, false},
		// * does not cross /
		{"a*c", "abbbc", false, true},
		{"a*c", "ab/bc", false, false},
		// ** crosses
		{"a/**/c", "a/c", false, true},
		{"a/**/c", "a/b/c", false, true},
		{"a/**/c", "a/b/b2/c", false, true},
		{"**/foo", "foo", false, true},
		{"**/foo", "x/y/foo", false, true},
		{"a/**", "a/b", false, true},
		{"a/**", "a/b/c", false, true},
		{"a/**", "a", true, false},
		// character classes
		{"file[0-9].txt", "file5.txt", false, true},
		{"file[0-9].txt", "fileA.txt", false, false},
		{"file[!0-9].txt", "fileA.txt", false, true},
		{"file[!0-9].txt", "file5.txt", false, false},
		// comments and escapes
		{"#comment\n\\#literal", "#literal", false, true},
		{"\\!important", "!important", false, true},
		// dir-only pattern also blocks contents via parent rule
		{"node_modules/", "node_modules/x/y.js", false, true},
	}
	for _, c := range cases {
		m := matcherFrom(t, c.patterns)
		got := m.IsIgnored(c.path, c.isDir)
		if got != c.want {
			t.Errorf("patterns %q path %q isDir=%v: got %v want %v",
				c.patterns, c.path, c.isDir, got, c.want)
		}
	}
}

// TestDifferentialAgainstGit checks that the matcher is
// differentially tested against `git check-ignore` over a generated corpus.
func TestDifferentialAgainstGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	patterns := []string{
		"*.pem",
		"*.env",
		"!keep.env",
		"/.env",
		"secrets/",
		"!secrets/README.md", // ineffective: parent rule
		"config/*.key",
		"**/creds",
		"deep/**/x.txt",
		"data/**",
		"file[0-9].log",
		"file[!a-z].md",
		"a?b",
		"tmp*",
		"!tmpkeep",
		"/anchored.txt",
		"doc/*.pdf",
		"\\#hash.txt",
		"\\!bang.txt",
		"trail/",
		"*.swp",
		"[ab]cd.txt",
	}

	files := []string{
		"server.pem", "nested/server.pem", "x.pem.txt",
		"prod.env", "keep.env", "sub/keep.env", "sub/prod.env",
		".env", "sub/.env",
		"secrets/README.md", "secrets/api.txt", "secrets/deep/k.txt",
		"config/a.key", "config/sub/b.key", "other/config/c.key",
		"creds", "a/creds", "a/b/creds", "credsx",
		"deep/x.txt", "deep/a/x.txt", "deep/a/b/x.txt", "deep/y.txt",
		"data/f1", "data/d/f2",
		"file1.log", "filea.log", "file9.log",
		"file1.md", "filez.md", "fileZ.md",
		"axb", "ab", "a/b",
		"tmp1", "tmpkeep", "sub/tmp2", "sub/tmpkeep",
		"anchored.txt", "sub/anchored.txt",
		"doc/m.pdf", "doc/sub/n.pdf",
		"#hash.txt", "!bang.txt",
		"trail/inside.txt", "plain.txt",
		"editor.swp", "d1/d2/d3/e.swp",
		"acd.txt", "bcd.txt", "ccd.txt",
	}
	dirs := []string{"trail", "secrets", "emptydir"}

	repo := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		_ = cmd.Run()
		return out.String()
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"),
		[]byte(strings.Join(patterns, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A path that is a prefix of another must materialize as a directory.
	interior := map[string]bool{}
	for _, d := range dirs {
		interior[d] = true
	}
	for _, f := range files {
		if i := strings.LastIndex(f, "/"); i > 0 {
			for p := f[:i]; p != "" && p != "."; p = filepath.Dir(p) {
				if p == "/" {
					break
				}
				interior[p] = true
			}
		}
	}
	for _, f := range files {
		if interior[f] {
			continue
		}
		p := filepath.Join(repo, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for d := range interior {
		if err := os.MkdirAll(filepath.Join(repo, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Ask git about every path.
	cmd := exec.Command("git", "check-ignore", "--stdin", "-z")
	cmd.Dir = repo
	var allPaths []string
	allPaths = append(allPaths, files...)
	allPaths = append(allPaths, dirs...)
	cmd.Stdin = strings.NewReader(strings.Join(allPaths, "\x00") + "\x00")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() > 1 {
			t.Fatalf("git check-ignore: %v", err)
		}
	}
	gitIgnored := map[string]bool{}
	for _, p := range strings.Split(out.String(), "\x00") {
		if p != "" {
			gitIgnored[p] = true
		}
	}

	m := matcherFrom(t, strings.Join(patterns, "\n"))
	for _, p := range allPaths {
		got := m.IsIgnored(p, interior[p])
		want := gitIgnored[p]
		if got != want {
			t.Errorf("path %q: agentbox=%v git=%v", p, got, want)
		}
	}
}

// TestGeneratedCorpus fuzzes structured random patterns and paths against
// git check-ignore.
func TestGeneratedCorpus(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if testing.Short() {
		t.Skip("short mode")
	}

	names := []string{"a", "b", "cc", "d1", "x-y", "z_9", "spec.md", "k.pem", "v.env"}
	pats := []string{
		"*.pem", "k.*", "??.md", "[abc]", "a/**", "**/b", "a/**/cc",
		"/a", "b/", "!cc", "d?", "[!a]", "x-*", "*_9", "a/b", "!a/b",
	}

	// Build a path corpus of depth <= 3 over the name alphabet.
	var paths []string
	for _, n1 := range names {
		paths = append(paths, n1)
		for _, n2 := range names[:5] {
			paths = append(paths, n1+"/"+n2)
			for _, n3 := range names[:3] {
				paths = append(paths, n1+"/"+n2+"/"+n3)
			}
		}
	}

	// Several pattern-file permutations exercise ordering (last match wins).
	sets := [][]string{
		pats,
		reverse(pats),
		append(append([]string{}, pats[:8]...), "!k.pem", "*.env"),
		{"a/", "!a/b", "**/spec.md", "d1/**", "!d1/a"},
	}

	for si, set := range sets {
		repo := t.TempDir()
		git := func(args ...string) {
			cmd := exec.Command("git", args...)
			cmd.Dir = repo
			if err := cmd.Run(); err != nil {
				t.Fatalf("git %v: %v", args, err)
			}
		}
		git("init", "-q")
		if err := os.WriteFile(filepath.Join(repo, ".gitignore"),
			[]byte(strings.Join(set, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// Materialize: leaf entries as files, interior as dirs.
		interior := map[string]bool{}
		for _, p := range paths {
			if i := strings.LastIndex(p, "/"); i > 0 {
				interior[p[:i]] = true
			}
		}
		for _, p := range paths {
			full := filepath.Join(repo, p)
			if interior[p] {
				_ = os.MkdirAll(full, 0o755)
			} else {
				_ = os.MkdirAll(filepath.Dir(full), 0o755)
				_ = os.WriteFile(full, []byte("x"), 0o644)
			}
		}

		cmd := exec.Command("git", "check-ignore", "--stdin", "-z")
		cmd.Dir = repo
		cmd.Stdin = strings.NewReader(strings.Join(paths, "\x00") + "\x00")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() > 1 {
				t.Fatalf("git check-ignore: %v", err)
			}
		}
		gitIgnored := map[string]bool{}
		for _, p := range strings.Split(out.String(), "\x00") {
			if p != "" {
				gitIgnored[p] = true
			}
		}

		m := matcherFrom(t, strings.Join(set, "\n"))
		for _, p := range paths {
			got := m.IsIgnored(p, interior[p])
			if got != gitIgnored[p] {
				t.Errorf("set %d path %q (dir=%v): agentbox=%v git=%v\npatterns:\n%s",
					si, p, interior[p], got, gitIgnored[p], strings.Join(set, "\n"))
			}
		}
	}
}

func reverse(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[len(in)-1-i] = s
	}
	return out
}

func TestTrailingSpaceHandling(t *testing.T) {
	m := matcherFrom(t, "foo   \nbar\\ \n")
	if !m.IsIgnored("foo", false) {
		t.Error("unescaped trailing spaces should be trimmed")
	}
	if !m.IsIgnored("bar ", false) {
		t.Error("escaped trailing space should be preserved")
	}
	if m.IsIgnored("bar", false) {
		t.Error("\"bar\\ \" must not match \"bar\"")
	}
}

func FuzzCompileNoPanic(f *testing.F) {
	seeds := []string{"*.pem", "a[", "**", "[!]", "\\", "a/**/b", "!x", "[a-]", "[]a]"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		r, ok := CompileLine(line, "fuzz", 1)
		if ok && r.re == nil {
			t.Fatal("compiled rule with nil regexp")
		}
		if ok {
			r.re.MatchString("some/path/x.txt")
		}
	})
}

func ExampleMatcher_Explain() {
	m := &Matcher{}
	_ = m.AddFile(strings.NewReader("*.pem\n!public.pem\n"), ".agentignore")
	ignored, rule := m.Explain("certs/server.pem", false)
	fmt.Println(ignored, rule.Pattern, rule.Line)
	// Output: true *.pem 1
}
