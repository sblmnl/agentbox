// Package netpol implements the tier-independent network policy language:
// modes, bundles, allowlist evaluation, and proxy configuration
// generation.
package netpol

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Modes.
const (
	ModeOff   = "off"   // no egress path exists; no proxy
	ModeProxy = "proxy" // no route out; all egress via the policy proxy
	ModeOpen  = "open"  // ordinary network access; warns every invocation
)

// Bundles are tool-maintained named sets, versioned with the release.
// Optional telemetry endpoints live in separate "*:telemetry"
// bundles so the default is silence rather than blocked-request noise.
var Bundles = map[string][]string{
	"agent:claude-code": {
		"api.anthropic.com",
		"claude.ai",
		"platform.claude.com",
		"statsig.anthropic.com",
		"console.anthropic.com",
	},
	"agent:claude-code:telemetry": {
		"o1158394.ingest.sentry.io",
	},
	"github": {
		"github.com",
		"api.github.com",
		"codeload.github.com",
		"raw.githubusercontent.com",
		"objects.githubusercontent.com",
		"release-assets.githubusercontent.com",
		"ghcr.io",
		".pkg.github.com",
	},
	"gitlab": {
		"gitlab.com",
		"registry.gitlab.com",
	},
	"npm": {
		"registry.npmjs.org",
	},
	"pypi": {
		"pypi.org",
		"files.pythonhosted.org",
	},
	"nuget": {
		"api.nuget.org",
		"www.nuget.org",
		"nuget.org",
		".blob.core.windows.net",
	},
	"crates": {
		"crates.io",
		"static.crates.io",
		"index.crates.io",
	},
	"go": {
		"proxy.golang.org",
		"sum.golang.org",
		"index.golang.org",
	},
	"rubygems": {
		"rubygems.org",
		"index.rubygems.org",
	},
	"docker-hub": {
		"registry-1.docker.io",
		"auth.docker.io",
		"production.cloudflare.docker.com",
		"hub.docker.com",
	},
	"ubuntu": {
		"archive.ubuntu.com",
		"security.ubuntu.com",
		"ports.ubuntu.com",
		"esm.ubuntu.com",
	},
	"debian": {
		"deb.debian.org",
		"security.debian.org",
	},
}

// BundleNames returns the sorted bundle registry, for `bundles --list` and
// shell completion.
func BundleNames() []string {
	names := make([]string, 0, len(Bundles))
	for n := range Bundles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// TelemetryDisableVars maps an agent bundle to the environment that mutes
// its telemetry when the ":telemetry" bundle is not included.
var TelemetryDisableVars = map[string]map[string]string{
	"agent:claude-code": {
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
		"DISABLE_TELEMETRY":                        "1",
		"DISABLE_ERROR_REPORTING":                  "1",
	},
}

// Policy is the evaluated egress policy for one box. The JSON tags matter:
// `--dry-run --json` is how the egress policy is inspected, so its shape is
// part of the documented contract.
type Policy struct {
	Mode  string   `json:"mode"`
	Allow []string `json:"allow"` // resolved effective allow set (bundles ∪ allow, sorted)
	Deny  []string `json:"deny"`  // deny entries; evaluated first, always win
	Audit bool     `json:"audit"`
}

// Resolve expands bundles and validates entries. Effective set = union of
// resolved bundles and allow, minus deny. IP literals and CIDR are
// unsupported in this release and MUST error rather than be silently
// dropped.
func Resolve(mode string, bundleNames, allow, deny []string) (*Policy, error) {
	p := &Policy{Mode: mode, Audit: true}
	seen := map[string]bool{}
	addAllow := func(d string) {
		d = normalizeDomain(d)
		if d != "" && !seen[d] {
			seen[d] = true
			p.Allow = append(p.Allow, d)
		}
	}
	for _, b := range bundleNames {
		domains, ok := Bundles[b]
		if !ok {
			return nil, fmt.Errorf("unknown bundle %q (known bundles: %s)", b, strings.Join(BundleNames(), ", "))
		}
		for _, d := range domains {
			addAllow(d)
		}
	}
	for _, d := range allow {
		if err := checkEntry(d); err != nil {
			return nil, err
		}
		addAllow(d)
	}
	for _, d := range deny {
		if err := checkEntry(d); err != nil {
			return nil, err
		}
		p.Deny = append(p.Deny, normalizeDomain(d))
	}
	sort.Strings(p.Allow)
	sort.Strings(p.Deny)
	return p, nil
}

func checkEntry(d string) error {
	host := strings.TrimPrefix(d, ".")
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf("allowlist entry %q: IP literals are not supported in this release; use a domain (refusing to drop the entry silently)", d)
	}
	if _, _, err := net.ParseCIDR(host); err == nil {
		return fmt.Errorf("allowlist entry %q: CIDR ranges are not supported in this release; use a domain (refusing to drop the entry silently)", d)
	}
	if host == "" || strings.ContainsAny(host, " /:") {
		return fmt.Errorf("allowlist entry %q: not a valid domain", d)
	}
	return nil
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
}

// Allowed evaluates one host against the policy. Deny is evaluated first
// and wins. A leading '.' entry matches the domain and its
// subdomains; a bare entry matches exactly.
func (p *Policy) Allowed(host string) bool {
	host = normalizeDomain(host)
	if hostMatchesAny(host, p.Deny) {
		return false
	}
	return hostMatchesAny(host, p.Allow)
}

func hostMatchesAny(host string, entries []string) bool {
	for _, e := range entries {
		if strings.HasPrefix(e, ".") {
			base := e[1:]
			if host == base || strings.HasSuffix(host, e) {
				return true
			}
		} else if host == e {
			return true
		}
	}
	return false
}

// ProxyEnv returns both casings of the three proxy variables:
// libcurl deliberately ignores uppercase HTTP_PROXY while honoring
// uppercase HTTPS_PROXY, and other tools read only the uppercase forms.
func ProxyEnv(proxyURL string) map[string]string {
	noProxy := "localhost,127.0.0.1,::1"
	return map[string]string{
		"http_proxy":  proxyURL,
		"HTTP_PROXY":  proxyURL,
		"https_proxy": proxyURL,
		"HTTPS_PROXY": proxyURL,
		"no_proxy":    noProxy,
		"NO_PROXY":    noProxy,
	}
}

// SquidConfig renders the sidecar proxy configuration:
// default-deny with an explicit terminal deny, one log line per request
// including denials, no caching, client-identifying headers stripped, and
// idle/request timeouts long enough for streamed model responses.
func (p *Policy) SquidConfig(listenPort int, readTimeout, requestTimeout string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# generated by agentbox; do not edit\n")
	fmt.Fprintf(&b, "http_port %d\n", listenPort)
	b.WriteString(`
# audit trail: one line per request, denials distinguishable
logformat agentbox %ts.%03tu %>a %Ss/%03>Hs %rm %ru
access_log stdio:/var/log/squid/access.log agentbox
cache deny all

# streamed model responses must not be severed mid-flight
`)
	fmt.Fprintf(&b, "read_timeout %s\n", squidDuration(readTimeout))
	fmt.Fprintf(&b, "request_timeout %s\n", squidDuration(requestTimeout))
	b.WriteString(`
# client-identifying headers stripped
via off
forwarded_for delete
request_header_access X-Forwarded-For deny all
request_header_access Via deny all

acl SSL_ports port 443
acl CONNECT method CONNECT
`)
	for i, d := range p.Deny {
		fmt.Fprintf(&b, "acl deny%d dstdomain %s\n", i, d)
		fmt.Fprintf(&b, "http_access deny deny%d\n", i)
	}
	if len(p.Allow) > 0 {
		b.WriteString("acl allowed dstdomain")
		for _, d := range p.Allow {
			b.WriteString(" " + d)
		}
		b.WriteString("\n")
		b.WriteString("http_access allow CONNECT allowed SSL_ports\n")
		b.WriteString("http_access allow allowed\n")
	}
	b.WriteString("\n# explicit terminal deny (default-deny)\nhttp_access deny all\n")
	return b.String()
}

func squidDuration(d string) string {
	d = strings.TrimSpace(d)
	switch {
	case strings.HasSuffix(d, "h"):
		return strings.TrimSuffix(d, "h") + " hours"
	case strings.HasSuffix(d, "m"):
		return strings.TrimSuffix(d, "m") + " minutes"
	case strings.HasSuffix(d, "s"):
		return strings.TrimSuffix(d, "s") + " seconds"
	}
	return d + " minutes"
}
