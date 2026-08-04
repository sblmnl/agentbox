package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Layer names used in --origin output, lowest precedence first.
const (
	LayerBuiltin   = "built-in"
	LayerSystem    = "/etc/agentbox/config.toml"
	LayerUser      = "user"
	LayerWorkspace = "workspace"
	LayerProfile   = "profile"
	LayerEnv       = "environment"
	LayerFlags     = "flags"
)

// LoadOptions carries the inputs that select and shape layers.
type LoadOptions struct {
	WorkspaceRoot string
	ProfileName   string // --profile / AGENTBOX_PROFILE; [box].profile read from merge
	ConfigFile    string // --config: replaces the workspace layer
	NoConfig      bool   // --no-config: built-in defaults only
	SystemPath    string // override for tests; "" = /etc/agentbox/config.toml
	UserConfigDir string // override for tests; "" = $XDG_CONFIG_HOME/agentbox
	Environ       []string
}

// Result is the outcome of loading: the typed config, the merged tree with
// origins, and non-fatal warnings the CLI must print to stderr.
type Result struct {
	Config   *Config
	Merged   *Merged
	Warnings []string
	// Layers actually applied, in order, for diagnostics.
	Layers []string

	// Workspace-config trust inputs. WorkspaceFile is the top-level
	// workspace config actually applied; WorkspaceChain is that file plus
	// every extends base it pulled in, in application order; Restricted lists
	// the dotted keys the workspace layer supplied that agentbox refuses to
	// honor until the config is trusted: host-side hooks and host mounts.
	WorkspaceFile  string
	WorkspaceChain []string
	Restricted     []string
}

// SchemaError aggregates one layer's validation failures; the CLI maps it to
// exit 78 (EX_CONFIG).
type SchemaError struct {
	Layer  string
	Errors []error
}

func (e *SchemaError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "invalid configuration in %s:", e.Layer)
	for _, err := range e.Errors {
		b.WriteString("\n  " + err.Error())
	}
	return b.String()
}

func UserConfigDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "agentbox")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agentbox")
}

// Load merges all layers in precedence order. Flag overrides
// are applied by the caller onto Result.Merged before Decode via ApplyFlags.
func Load(opts LoadOptions) (*Result, error) {
	res := &Result{Merged: NewMerged()}

	apply := func(tree map[string]any, name string) error {
		if errs := ValidateTree(tree); len(errs) > 0 {
			return &SchemaError{Layer: name, Errors: errs}
		}
		res.Merged.Apply(tree, name)
		res.Layers = append(res.Layers, name)
		return nil
	}

	builtin, err := parseTOML([]byte(BuiltinDefaults))
	if err != nil {
		return nil, fmt.Errorf("internal error: built-in defaults do not parse: %w", err)
	}
	if err := apply(builtin, LayerBuiltin); err != nil {
		return nil, err
	}

	if !opts.NoConfig {
		system := opts.SystemPath
		if system == "" {
			system = "/etc/agentbox/config.toml"
		}
		if err := applyFile(res, system, LayerSystem, apply, nil); err != nil {
			return nil, err
		}

		userDir := opts.UserConfigDir
		if userDir == "" {
			userDir = UserConfigDir()
		}
		if err := applyFile(res, filepath.Join(userDir, "config.toml"), LayerUser, apply, nil); err != nil {
			return nil, err
		}

		// Workspace layer: exactly one file participates; both names present
		// is an error.
		wsFile := opts.ConfigFile
		if wsFile == "" && opts.WorkspaceRoot != "" {
			plain := filepath.Join(opts.WorkspaceRoot, "agentbox.toml")
			hidden := filepath.Join(opts.WorkspaceRoot, ".agentbox.toml")
			pOK := fileExists(plain)
			hOK := fileExists(hidden)
			if pOK && hOK {
				return nil, &SchemaError{Layer: LayerWorkspace, Errors: []error{
					errors.New("both agentbox.toml and .agentbox.toml exist in the workspace root; remove one"),
				}}
			}
			if pOK {
				wsFile = plain
			} else if hOK {
				wsFile = hidden
			}
		}
		if wsFile != "" {
			if err := applyFile(res, wsFile, LayerWorkspace, apply, map[string]bool{}); err != nil {
				return nil, err
			}
		}

		// Profile overlay: --profile, then AGENTBOX_PROFILE, then
		// [box].profile from the merge so far.
		profile := opts.ProfileName
		if profile == "" {
			profile = envLookup(opts.Environ, "AGENTBOX_PROFILE")
		}
		if profile == "" {
			if v, ok := res.Merged.Lookup("box.profile").(string); ok {
				profile = v
			}
		}
		if profile != "" {
			if err := applyProfile(res, profile, userDir, apply); err != nil {
				return nil, err
			}
		}

		// Environment layer: AGENTBOX_SECTION__KEY=value.
		envTree := envToTree(opts.Environ)
		if len(envTree) > 0 {
			if err := apply(envTree, LayerEnv); err != nil {
				return nil, err
			}
		}
	}

	return finish(res)
}

// ApplyFlags overlays CLI flag values (highest layer) and re-decodes.
func (r *Result) ApplyFlags(tree map[string]any) error {
	if len(tree) == 0 {
		return nil
	}
	if errs := ValidateTree(tree); len(errs) > 0 {
		return &SchemaError{Layer: LayerFlags, Errors: errs}
	}
	r.Merged.Apply(tree, LayerFlags)
	r.Layers = append(r.Layers, LayerFlags)
	fin, err := finish(r)
	if err != nil {
		return err
	}
	*r = *fin
	return nil
}

func finish(res *Result) (*Result, error) {
	cfg, err := Decode(res.Merged.Tree)
	if err != nil {
		return nil, &SchemaError{Layer: "merged configuration", Errors: []error{err}}
	}
	res.Config = cfg
	// A relative [image].dockerfile path is resolved against the directory of
	// the config file that supplied it, matching `extends`. This makes a
	// baseline Dockerfile kept next to the user config in $XDG_CONFIG_HOME
	// resolve the same way from every project.
	if p := cfg.Image.Dockerfile; p != "" && !filepath.IsAbs(p) {
		if base := layerFileDir(res.Merged.Origin["image.dockerfile"]); base != "" {
			cfg.Image.Dockerfile = filepath.Join(base, p)
		} else if wd, werr := os.Getwd(); werr == nil {
			// Supplied by a non-file layer (environment/flags): resolve against
			// the current directory, the natural base for a CLI-supplied path.
			cfg.Image.Dockerfile = filepath.Join(wd, p)
		}
	}
	res.Warnings = res.Warnings[:0]
	if len(cfg.Security.Container.CapAdd) > 0 {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("security.container.cap_add is non-empty (%s): added capabilities weaken the container boundary",
				strings.Join(cfg.Security.Container.CapAdd, ", ")))
	}
	return res, nil
}

// applyFile loads one TOML file, resolving extends chains with cycle
// detection, lower-precedence first.
func applyFile(res *Result, path, layerName string, apply func(map[string]any, string) error, seen map[string]bool) error {
	if !fileExists(path) {
		return nil
	}
	return applyFileChain(res, path, layerName, apply, map[string]bool{})
}

func applyFileChain(res *Result, path, layerName string, apply func(map[string]any, string) error, seen map[string]bool) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if seen[abs] {
		return &SchemaError{Layer: layerName, Errors: []error{
			fmt.Errorf("extends cycle detected at %s", abs)}}
	}
	seen[abs] = true

	data, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("reading %s: %w", abs, err)
	}
	tree, err := parseTOML(data)
	if err != nil {
		return &SchemaError{Layer: abs, Errors: []error{err}}
	}
	if ext, ok := tree["extends"].(string); ok && ext != "" {
		base := ext
		if !filepath.IsAbs(base) {
			base = filepath.Join(filepath.Dir(abs), base)
		}
		if !fileExists(base) {
			return &SchemaError{Layer: abs, Errors: []error{
				fmt.Errorf("extends: %q does not exist", ext)}}
		}
		if err := applyFileChain(res, base, layerName+" (extends)", apply, seen); err != nil {
			return err
		}
	}
	delete(tree, "extends")

	if strings.HasPrefix(layerName, LayerWorkspace) {
		if _, hasLimits := tree["limits"]; hasLimits {
			res.Warnings = append(res.Warnings,
				"[limits] in a workspace config is ignored for enforcement decisions on other projects; it belongs in user or system configuration")
		}
		// Trust inputs: the workspace layer — including any extends
		// base it pulls in — is repo-controlled, so record which privileged
		// keys it supplies and which files back the trust digest.
		if layerName == LayerWorkspace {
			res.WorkspaceFile = abs
		}
		res.WorkspaceChain = append(res.WorkspaceChain, abs)
		res.Restricted = append(res.Restricted, restrictedIn(tree)...)
	}
	name := layerName
	// Record the backing file path in the origin for file-backed layers,
	// including their extends bases ("<layer> (extends)"), so a relative
	// [image].dockerfile can be resolved against the file that set it.
	if strings.HasPrefix(layerName, LayerWorkspace) || strings.HasPrefix(layerName, LayerUser) {
		name = layerName + ":" + abs
	}
	return apply(tree, name)
}

// applyProfile resolves a named profile: first [profiles.NAME] from the
// merge so far, else $XDG_CONFIG_HOME/agentbox/profiles/NAME.toml.
func applyProfile(res *Result, name, userDir string, apply func(map[string]any, string) error) error {
	layer := LayerProfile + ":" + name
	if body, ok := res.Merged.Lookup("profiles." + name).(map[string]any); ok {
		// A profile defined inside the workspace config is repo-controlled:
		// privileged keys it supplies are restricted the same way the
		// workspace layer's are. Origin tracking tells us which
		// layer defined each key of the profile body.
		for _, k := range restrictedIn(body) {
			if strings.HasPrefix(res.Merged.Origin["profiles."+name+"."+k], LayerWorkspace) {
				res.Restricted = append(res.Restricted, "profiles."+name+"."+k)
			}
		}
		return apply(body, layer)
	}
	pf := filepath.Join(userDir, "profiles", name+".toml")
	if fileExists(pf) {
		data, err := os.ReadFile(pf)
		if err != nil {
			return err
		}
		tree, err := parseTOML(data)
		if err != nil {
			return &SchemaError{Layer: pf, Errors: []error{err}}
		}
		return apply(tree, layer)
	}
	return &SchemaError{Layer: layer, Errors: []error{
		fmt.Errorf("profile %q not found: no [profiles.%s] in any config layer and no %s", name, name, pf)}}
}

// envToTree converts AGENTBOX_SECTION__KEY=value variables into a config
// tree. Double underscore separates path components; single underscores are
// preserved inside a component (AGENTBOX_NETWORK__MODE=none →
// network.mode). Values parse as TOML scalars where possible.
func envToTree(environ []string) map[string]any {
	tree := map[string]any{}
	reserved := map[string]bool{
		"AGENTBOX_PROFILE": true, "AGENTBOX_WORKSPACE": true,
	}
	for _, kv := range environ {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 || !strings.HasPrefix(kv, "AGENTBOX_") {
			continue
		}
		key, val := kv[:eq], kv[eq+1:]
		if reserved[key] {
			continue
		}
		parts := strings.Split(strings.ToLower(strings.TrimPrefix(key, "AGENTBOX_")), "__")
		cur := tree
		for i, p := range parts {
			if i == len(parts)-1 {
				cur[p] = coerceScalar(val)
				break
			}
			next, ok := cur[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				cur[p] = next
			}
			cur = next
		}
	}
	return tree
}

func coerceScalar(v string) any {
	switch v {
	case "true":
		return true
	case "false":
		return false
	}
	if strings.HasPrefix(v, "[") {
		if arr, err := parseTOML([]byte("x = " + v)); err == nil {
			return arr["x"]
		}
	}
	var i int64
	if _, err := fmt.Sscanf(v, "%d", &i); err == nil && fmt.Sprintf("%d", i) == v {
		return i
	}
	return v
}

func envLookup(environ []string, key string) string {
	for _, kv := range environ {
		if strings.HasPrefix(kv, key+"=") {
			return kv[len(key)+1:]
		}
	}
	return ""
}

// restrictedIn returns the dotted keys in a raw layer tree that agentbox
// refuses to honor from an untrusted workspace config: host-side
// hooks, which execute commands on the host, and workspace mounts, which can
// expose host paths like ~/.ssh to the guest.
func restrictedIn(tree map[string]any) []string {
	var out []string
	if hooks, ok := tree["hooks"].(map[string]any); ok {
		keys := make([]string, 0, len(hooks))
		for k := range hooks {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if arr, ok := hooks[k].([]any); ok && len(arr) > 0 {
				out = append(out, "hooks."+k)
			}
		}
	}
	if ws, ok := tree["workspace"].(map[string]any); ok {
		switch m := ws["mounts"].(type) {
		case []map[string]any:
			if len(m) > 0 {
				out = append(out, "workspace.mounts")
			}
		case []any:
			if len(m) > 0 {
				out = append(out, "workspace.mounts")
			}
		}
	}
	return out
}

// layerFileDir returns the directory of the config file behind an origin
// attribution, or "" when the layer is not backed by a file. User and
// workspace layers are recorded as "<layer>:<abs path>"; the system layer's
// name is the path itself.
func layerFileDir(origin string) string {
	if i := strings.IndexByte(origin, ':'); i >= 0 {
		if p := origin[i+1:]; filepath.IsAbs(p) {
			return filepath.Dir(p)
		}
	}
	if filepath.IsAbs(origin) {
		return filepath.Dir(origin)
	}
	return ""
}

// DigestFiles hashes a set of files (path and content) into the trust digest
// recorded by `agentbox trust` and compared on every load.
func DigestFiles(paths []string) string {
	h := sha256.New()
	for _, p := range paths {
		data, _ := os.ReadFile(p)
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func parseTOML(data []byte) (map[string]any, error) {
	var tree map[string]any
	if err := toml.Unmarshal(data, &tree); err != nil {
		return nil, err
	}
	return tree, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
