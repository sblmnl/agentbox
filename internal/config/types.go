package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Config is the effective merged configuration, decoded from the merged
// tree. Field defaults come from the built-in defaults layer.
type Config struct {
	Version int

	Box struct {
		Name           string
		Profile        string
		DefaultCommand []string
		DefaultAgent   string
		IdleTimeout    string
	}
	Project struct {
		MaxBoxes int
	}
	Workspace struct {
		Mount    string
		ReadOnly bool
		TreeMode string
		Mounts   []Mount
	}
	Toolchains map[string]string
	Image      struct {
		Ref        string
		Base       string
		Dockerfile string
		Packages   []string
		BuildArgs  map[string]string
	}
	Agents struct {
		Install []string
		Channel string
	}
	Network struct {
		Mode    string
		Bundles []string
		Allow   []string
		Deny    []string
		Audit   bool
		Proxy   struct {
			ReadTimeout    string
			RequestTimeout string
		}
	}
	Resources struct {
		Memory    string
		CPUs      float64
		Pids      int
		TmpfsSize string
		Nofile    int
	}
	Security struct {
		MinIsolation string
		Backend      string
		StripSetuid  bool
		MaskMode     string
		Container    struct {
			ReadOnlyRoot    bool
			NoNewPrivileges bool
			CapDrop         []string
			CapAdd          []string
			Userns          string
			Seccomp         string
			GuestRoot       string
		}
		VM struct {
			Hypervisor    string
			Runtime       string
			GuestRoot     string
			NestedDocker  bool
			MemoryBacking string
		}
	}
	Masking struct {
		IgnoreFiles   []string
		TmpfsSize     string
		FilesReadonly bool
	}
	Variables   map[string]string
	Passthrough []string
	Hooks       struct {
		PreUp   []string
		PostUp  []string
		PreExec []string
	}
	Limits struct {
		MaxBoxes       int
		MaxTotalMemory string
		OnLimit        string
	}
}

type Mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Mode   string `json:"mode"`
}

// BuiltinDefaults is the lowest configuration layer, compiled in.
const BuiltinDefaults = `
version = 1

[box]
default_command = ["bash", "-l"]
idle_timeout    = "30m"

[project]
max_boxes = 4

[workspace]
mount     = "/workspace"
readonly  = false
tree_mode = "auto"

[agents]
channel = "stable"

[network]
mode    = "proxy"
bundles = []
allow   = []
deny    = []
audit   = true

[network.proxy]
read_timeout    = "1h"
request_timeout = "5m"

[resources]
memory     = "8g"
cpus       = 4
pids       = 4096
tmpfs_size = "4g"
nofile     = 65536

[security]
min_isolation = "container"
strip_setuid  = true
mask_mode     = "auto"

[security.container]
read_only_root    = true
no_new_privileges = true
cap_drop          = ["ALL"]
cap_add           = []
userns            = "auto"
seccomp           = "default"
guest_root        = "deny"

[security.vm]
hypervisor     = "auto"
runtime        = "auto"
guest_root     = "allow"
nested_docker  = false
memory_backing = "balloon"

[masking]
ignore_files   = [".agentignore"]
tmpfs_size     = "1m"
files_readonly = true

[image]
base = "ubuntu:26.04"

[limits]
max_boxes        = 12
max_total_memory = "48g"
on_limit         = "error"
`

// Decode converts a merged raw tree into a typed Config.
func Decode(tree map[string]any) (*Config, error) {
	c := &Config{}
	g := getter{tree}
	c.Version = g.i("version", 1)

	c.Box.Name = g.s("box.name", "")
	c.Box.Profile = g.s("box.profile", "")
	c.Box.DefaultCommand = g.list("box.default_command")
	c.Box.DefaultAgent = g.s("box.default_agent", "")
	c.Box.IdleTimeout = g.s("box.idle_timeout", "30m")
	c.Project.MaxBoxes = g.i("project.max_boxes", 4)

	c.Workspace.Mount = g.s("workspace.mount", "/workspace")
	c.Workspace.ReadOnly = g.b("workspace.readonly", false)
	c.Workspace.TreeMode = g.s("workspace.tree_mode", "auto")
	c.Workspace.Mounts = g.mounts("workspace.mounts")

	c.Toolchains = g.smap("toolchains")
	c.Image.Ref = g.s("image.ref", "")
	c.Image.Base = g.s("image.base", "ubuntu:26.04")
	c.Image.Dockerfile = g.s("image.dockerfile", "")
	c.Image.Packages = g.list("image.packages")
	c.Image.BuildArgs = g.smap("image.build_args")

	c.Agents.Install = g.list("agents.install")
	c.Agents.Channel = g.s("agents.channel", "stable")

	c.Network.Mode = g.s("network.mode", "proxy")
	c.Network.Bundles = g.list("network.bundles")
	c.Network.Allow = g.list("network.allow")
	c.Network.Deny = g.list("network.deny")
	c.Network.Audit = g.b("network.audit", true)
	c.Network.Proxy.ReadTimeout = g.s("network.proxy.read_timeout", "1h")
	c.Network.Proxy.RequestTimeout = g.s("network.proxy.request_timeout", "5m")

	c.Resources.Memory = g.s("resources.memory", "8g")
	c.Resources.CPUs = g.f("resources.cpus", 4)
	c.Resources.Pids = g.i("resources.pids", 4096)
	c.Resources.TmpfsSize = g.s("resources.tmpfs_size", "4g")
	c.Resources.Nofile = g.i("resources.nofile", 65536)

	c.Security.MinIsolation = g.s("security.min_isolation", "container")
	c.Security.Backend = g.s("security.backend", "")
	c.Security.StripSetuid = g.b("security.strip_setuid", true)
	c.Security.MaskMode = g.s("security.mask_mode", "auto")

	c.Security.Container.ReadOnlyRoot = g.b("security.container.read_only_root", true)
	c.Security.Container.NoNewPrivileges = g.b("security.container.no_new_privileges", true)
	c.Security.Container.CapDrop = g.list("security.container.cap_drop")
	c.Security.Container.CapAdd = g.list("security.container.cap_add")
	c.Security.Container.Userns = g.s("security.container.userns", "auto")
	c.Security.Container.Seccomp = g.s("security.container.seccomp", "default")
	c.Security.Container.GuestRoot = g.s("security.container.guest_root", "deny")

	c.Security.VM.Hypervisor = g.s("security.vm.hypervisor", "auto")
	c.Security.VM.Runtime = g.s("security.vm.runtime", "auto")
	c.Security.VM.GuestRoot = g.s("security.vm.guest_root", "allow")
	c.Security.VM.NestedDocker = g.b("security.vm.nested_docker", false)
	c.Security.VM.MemoryBacking = g.s("security.vm.memory_backing", "balloon")

	c.Masking.IgnoreFiles = g.list("masking.ignore_files")
	c.Masking.TmpfsSize = g.s("masking.tmpfs_size", "1m")
	c.Masking.FilesReadonly = g.b("masking.files_readonly", true)

	c.Variables = g.smap("variables")
	delete(c.Variables, "passthrough")
	c.Passthrough = g.list("variables.passthrough.names")

	c.Hooks.PreUp = g.list("hooks.pre_up")
	c.Hooks.PostUp = g.list("hooks.post_up")
	c.Hooks.PreExec = g.list("hooks.pre_exec")

	c.Limits.MaxBoxes = g.i("limits.max_boxes", 12)
	c.Limits.MaxTotalMemory = g.s("limits.max_total_memory", "48g")
	c.Limits.OnLimit = g.s("limits.on_limit", "error")

	if c.Version != 1 {
		return nil, fmt.Errorf("version: unsupported config version %d (this release supports version = 1)", c.Version)
	}
	return c, nil
}

type getter struct{ tree map[string]any }

func (g getter) at(path string) any {
	parts := strings.Split(path, ".")
	cur := any(g.tree)
	for _, p := range parts {
		t, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = t[p]
	}
	return cur
}

func (g getter) s(path, def string) string {
	if v, ok := g.at(path).(string); ok {
		return v
	}
	return def
}
func (g getter) b(path string, def bool) bool {
	if v, ok := g.at(path).(bool); ok {
		return v
	}
	return def
}
func (g getter) i(path string, def int) int {
	switch v := g.at(path).(type) {
	case int64:
		return int(v)
	case int:
		return v
	}
	return def
}
func (g getter) f(path string, def float64) float64 {
	switch v := g.at(path).(type) {
	case int64:
		return float64(v)
	case float64:
		return v
	}
	return def
}
func (g getter) list(path string) []string {
	v, ok := g.at(path).([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, el := range v {
		if s, ok := el.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
func (g getter) smap(path string) map[string]string {
	v, ok := g.at(path).(map[string]any)
	out := map[string]string{}
	if !ok {
		return out
	}
	for k, el := range v {
		if s, ok := el.(string); ok {
			out[k] = s
		}
	}
	return out
}
func (g getter) mounts(path string) []Mount {
	var out []Mount
	add := func(m map[string]any) {
		mt := Mount{Mode: "rw"}
		if s, ok := m["source"].(string); ok {
			mt.Source = s
		}
		if s, ok := m["target"].(string); ok {
			mt.Target = s
		}
		if s, ok := m["mode"].(string); ok {
			mt.Mode = s
		}
		out = append(out, mt)
	}
	switch v := g.at(path).(type) {
	case []map[string]any:
		for _, m := range v {
			add(m)
		}
	case []any:
		for _, el := range v {
			if m, ok := el.(map[string]any); ok {
				add(m)
			}
		}
	}
	return out
}

// ParseDuration parses "30m", "1h30m", "0".
func ParseDuration(s string) (time.Duration, error) {
	if s == "0" || s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}

// ParseSize parses "8g", "512m", "48g" into bytes.
func ParseSize(s string) (int64, error) {
	str := strings.ToLower(strings.TrimSuffix(strings.ToLower(s), "b"))
	mult := int64(1)
	switch {
	case strings.HasSuffix(str, "k"):
		mult, str = 1<<10, str[:len(str)-1]
	case strings.HasSuffix(str, "m"):
		mult, str = 1<<20, str[:len(str)-1]
	case strings.HasSuffix(str, "g"):
		mult, str = 1<<30, str[:len(str)-1]
	case strings.HasSuffix(str, "t"):
		mult, str = 1<<40, str[:len(str)-1]
	}
	n, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(n * float64(mult)), nil
}
