package app

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/sblmnl/agentbox/internal/netpol"
)

// CmdInit scaffolds agentbox.toml and .agentignore. Only init and
// allow ever write to the workspace, and only on explicit invocation.
func (c *Ctx) CmdInit(profile string) error {
	cfgPath := filepath.Join(c.Workspace, "agentbox.toml")
	if _, err := os.Stat(cfgPath); err == nil {
		return Usagef("%s already exists", cfgPath)
	}
	profileBlock := ""
	if profile != "" {
		profileBlock = fmt.Sprintf("\n[box]\nprofile = %q\n", profile)
	}
	cfg := fmt.Sprintf(`# agentbox project configuration — see agentbox.toml(5)
version = 1
%s
[toolchains]
# dotnet = "10"
# node   = "24"
# python = "3.13"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github"]
allow   = []

[security]
min_isolation = "container"
`, profileBlock)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return Softwaref("%v", err)
	}

	// The scaffolded .agentignore MUST NOT include .git.
	ignorePath := filepath.Join(c.Workspace, ".agentignore")
	if _, err := os.Stat(ignorePath); os.IsNotExist(err) {
		ignore := `# agentbox mask patterns — gitignore syntax
# Files matched here are unreadable from inside the box.
.env
.env.*
!.env.example
*.pem
*.key
id_rsa
id_ed25519
*.p12
*.pfx
credentials.json
secrets/
`
		if err := os.WriteFile(ignorePath, []byte(ignore), 0o644); err != nil {
			return Softwaref("%v", err)
		}
		c.Notef("wrote %s", ignorePath)
	}
	c.Notef("wrote %s", cfgPath)
	c.Notef("next: `agentbox doctor` to preflight, `agentbox config` to see the effective merge")
	return nil
}

// CmdAllow appends domains to the workspace config's allowlist.
func (c *Ctx) CmdAllow(domains []string) error {
	if len(domains) == 0 {
		return Usagef("allow requires at least one domain")
	}
	pol, err := netpol.Resolve("proxy", nil, domains, nil)
	if err != nil {
		return Configf("%v", err)
	}
	_ = pol

	cfgPath := filepath.Join(c.Workspace, "agentbox.toml")
	alt := filepath.Join(c.Workspace, ".agentbox.toml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if _, err := os.Stat(alt); err == nil {
			cfgPath = alt
		}
	}

	var tree map[string]any
	if data, err := os.ReadFile(cfgPath); err == nil {
		if err := toml.Unmarshal(data, &tree); err != nil {
			return Configf("%s: %v", cfgPath, err)
		}
	} else {
		tree = map[string]any{"version": int64(1)}
	}
	network, _ := tree["network"].(map[string]any)
	if network == nil {
		network = map[string]any{}
		tree["network"] = network
	}
	existing, _ := network["allow"].([]any)
	seen := map[string]bool{}
	for _, e := range existing {
		if s, ok := e.(string); ok {
			seen[s] = true
		}
	}
	added := 0
	for _, d := range domains {
		if !seen[d] {
			existing = append(existing, d)
			seen[d] = true
			added++
		}
	}
	network["allow"] = existing

	var buf bytes.Buffer
	buf.WriteString("# rewritten by `agentbox allow`; comments are not preserved\n")
	if err := toml.NewEncoder(&buf).Encode(tree); err != nil {
		return Softwaref("%v", err)
	}
	if err := os.WriteFile(cfgPath, buf.Bytes(), 0o644); err != nil {
		return Softwaref("%v", err)
	}
	// The user asked for this edit; do not invalidate their recorded trust.
	c.refreshTrustAfterRewrite()
	c.Notef("added %d domain(s) to %s", added, cfgPath)
	return nil
}
