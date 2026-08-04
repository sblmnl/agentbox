package identity

import (
	"math/rand"
	"strings"
	"testing"
)

func TestProjectKey(t *testing.T) {
	k1 := ProjectKey("/home/u/src/myapp")
	k2 := ProjectKey("/home/u/src/myapp")
	k3 := ProjectKey("/home/u/other/myapp")
	if k1 != k2 {
		t.Error("key must be deterministic")
	}
	// Same basename, different path: same slug, different digest (// the digest carries identity, the slug is for humans).
	if k1 == k3 {
		t.Error("different canonical paths must yield different keys")
	}
	if !strings.HasPrefix(k1, "myapp-") || len(k1) != len("myapp-")+8 {
		t.Errorf("key format: %s", k1)
	}
}

func TestSanitizeSlug(t *testing.T) {
	for in, want := range map[string]string{
		"MyApp":                 "myapp",
		"my.app":                "my-app",
		"-weird--":              "weird",
		"":                      "workspace",
		strings.Repeat("x", 40): strings.Repeat("x", 24),
	} {
		if got := SanitizeSlug(in); got != want {
			t.Errorf("SanitizeSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInstanceNames(t *testing.T) {
	for _, ok := range []string{"main", "exp-1", "a", "x_y", "b2"} {
		if !ValidInstanceName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-lead", "UPPER", strings.Repeat("a", 33), "sp ace"} {
		if ValidInstanceName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestGenerateName(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	taken := map[string]bool{}
	for i := 0; i < 100; i++ {
		n := GenerateName(taken, rng)
		if taken[n] {
			t.Fatalf("duplicate generated name %q", n)
		}
		taken[n] = true
		if IsBareInteger(n) {
			t.Fatalf("generated name %q is a bare integer", n)
		}
		if !ValidInstanceName(n) {
			t.Fatalf("generated name %q is not a valid instance name", n)
		}
	}
}

func TestTruncateForLimit(t *testing.T) {
	got := TruncateForLimit(strings.Repeat("s", 24), "deadbeef", "my-instance", 30)
	if len(got) > 30 {
		t.Errorf("length %d > 30: %s", len(got), got)
	}
	if !strings.Contains(got, "deadbeef") || !strings.Contains(got, "my-instance") {
		t.Errorf("digest and instance must survive truncation: %s", got)
	}
}
