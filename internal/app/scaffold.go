package app

import (
	"os"
	"path/filepath"
)

// CmdInit scaffolds agentbox.toml and .agentignore. It is the only command
// that writes to the workspace, and only on explicit invocation.
func (c *Ctx) CmdInit() error {
	cfgPath := filepath.Join(c.Workspace, "agentbox.toml")
	if _, err := os.Stat(cfgPath); err == nil {
		return Usagef("%s already exists", cfgPath)
	}
	cfg := `# agentbox project configuration — see agentbox.toml(5)
version = 1

[agents]
# Installs the agent's binary into the image. This and the "agent:*" entry in
# [network].bundles below are a pair: one puts the tool in the box, the other
# lets it reach its own endpoints. Removing one without the other gives you a
# box that either cannot run the agent or cannot let it talk.
install = ["claude-code"]
channel = "stable"

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
`
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
	c.Notef("next: `agentbox config` to see the effective merge, `agentbox --dry-run` to see the plan")
	return nil
}
