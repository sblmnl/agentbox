package netpol

import (
	"slices"
	"strings"
	"testing"
)

func TestAllowlistEvaluation(t *testing.T) {
	p, err := Resolve("proxy", []string{"github"}, []string{"registry.internal.example.com", ".corp.example.org"}, []string{"github.com"})
	if err != nil {
		t.Fatal(err)
	}
	// deny is evaluated first and wins, even against a bundle entry.
	if p.Allowed("github.com") {
		t.Error("denied domain must lose even when a bundle allows it")
	}
	if !p.Allowed("api.github.com") {
		t.Error("bundle domain must be allowed")
	}
	if !p.Allowed("registry.internal.example.com") {
		t.Error("explicit allow must work")
	}
	// leading '.' matches the domain and its subdomains.
	if !p.Allowed("corp.example.org") || !p.Allowed("deep.sub.corp.example.org") {
		t.Error("leading-dot entry must match domain and subdomains")
	}
	// a bare entry matches exactly, not subdomains.
	if p.Allowed("evil.registry.internal.example.com") {
		t.Error("bare entry must not match subdomains")
	}
	// default deny.
	if p.Allowed("exfil.example.net") {
		t.Error("unlisted domain must be denied")
	}
}

func TestIPAndCIDREntriesError(t *testing.T) {
	if _, err := Resolve("proxy", nil, []string{"10.0.0.1"}, nil); err == nil {
		t.Error("IP literal must error, not be dropped")
	}
	if _, err := Resolve("proxy", nil, []string{"10.0.0.0/8"}, nil); err == nil {
		t.Error("CIDR must error, not be dropped")
	}
	if _, err := Resolve("proxy", []string{"no-such-bundle"}, nil, nil); err == nil {
		t.Error("unknown bundle must error")
	}
}

func TestRequiredBundles(t *testing.T) {
	required := []string{
		"agent:claude-code", "github", "gitlab", "npm", "pypi", "nuget",
		"crates", "go", "rubygems", "docker-hub", "ubuntu", "debian",
	}
	for _, name := range required {
		if _, ok := Bundles[name]; !ok {
			t.Errorf("required bundle %q missing", name)
		}
	}
	for _, d := range Bundles["agent:claude-code"] {
		if strings.Contains(d, "sentry") {
			t.Errorf("telemetry endpoint %q must live in agent:claude-code:telemetry", d)
		}
	}
	// Without these the agent cannot start: it reaches platform.claude.com to
	// authenticate before it ever calls the API. Dropping one is a silent
	// break that only shows up as a connection error inside the box.
	for _, d := range []string{"api.anthropic.com", "platform.claude.com"} {
		if !slices.Contains(Bundles["agent:claude-code"], d) {
			t.Errorf("agent:claude-code must allow %q for the agent to connect", d)
		}
	}
}

func TestSquidConfigAndProxyEnv(t *testing.T) {
	p, err := Resolve("proxy", []string{"pypi"}, nil, []string{"bad.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	conf := p.SquidConfig(3128, "1h", "5m")
	for _, want := range []string{
		"http_access deny all", // explicit terminal deny
		"cache deny all",       // no caching
		"forwarded_for delete", // client-identifying headers stripped
		"pypi.org",             // allow entries present
		"bad.example.com",      // deny entries present
		"read_timeout 1 hours", // long enough for streamed responses
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("squid config missing %q:\n%s", want, conf)
		}
	}
	// deny rules appear before allow rules (deny wins).
	if strings.Index(conf, "bad.example.com") > strings.Index(conf, "http_access allow") {
		t.Error("deny rules must precede allow rules")
	}

	env := ProxyEnv("http://proxy:3128")
	for _, k := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY"} {
		if env[k] == "" {
			t.Errorf("proxy env missing %s (both casings)", k)
		}
	}
}
