package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Layer names used in --origin output, lowest precedence first.
//
// Four layers, and the order is the whole contract: compiled-in defaults, the
// user's own configuration, the workspace's committed configuration, and the
// flags typed at the prompt. There is deliberately no system layer, no
// environment layer and no profile layer -- each was a place a value could
// come from that nobody thought to look at.
const (
	LayerBuiltin   = "built-in"
	LayerUser      = "user"
	LayerWorkspace = "workspace"
	LayerFlags     = "flags"
)

// LoadOptions carries the inputs that select and shape layers.
type LoadOptions struct {
	WorkspaceRoot string
	ConfigFile    string // --config: replaces the workspace layer
	NoConfig      bool   // --no-config: built-in defaults only
	UserConfigDir string // override for tests; "" = $XDG_CONFIG_HOME/agentbox
}

// Result is the outcome of loading: the typed config, the merged tree with
// origins, and non-fatal warnings the CLI must print to stderr.
type Result struct {
	Config   *Config
	Merged   *Merged
	Warnings []string
	// Layers actually applied, in order, for diagnostics.
	Layers []string
	// WorkspaceFile is the workspace config actually applied, if any.
	WorkspaceFile string
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

// Load merges all layers in precedence order. Flag overrides are applied by
// the caller onto Result.Merged before Decode via ApplyFlags.
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
		userDir := opts.UserConfigDir
		if userDir == "" {
			userDir = UserConfigDir()
		}
		if err := applyFile(res, filepath.Join(userDir, "config.toml"), LayerUser, apply); err != nil {
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
			if err := applyFile(res, wsFile, LayerWorkspace, apply); err != nil {
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
	// the config file that supplied it. This makes a baseline Dockerfile kept
	// next to the user config in $XDG_CONFIG_HOME resolve the same way from
	// every project.
	if p := cfg.Image.Dockerfile; p != "" && !filepath.IsAbs(p) {
		if base := layerFileDir(res.Merged.Origin["image.dockerfile"]); base != "" {
			cfg.Image.Dockerfile = filepath.Join(base, p)
		} else if wd, werr := os.Getwd(); werr == nil {
			// Supplied by a non-file layer (flags): resolve against the
			// current directory, the natural base for a CLI-supplied path.
			cfg.Image.Dockerfile = filepath.Join(wd, p)
		}
	}
	res.Warnings = res.Warnings[:0]
	if len(cfg.Security.Container.CapAdd) > 0 {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("security.container.cap_add is non-empty (%s): added capabilities weaken the container boundary",
				strings.Join(cfg.Security.Container.CapAdd, ", ")))
	}
	res.Warnings = append(res.Warnings, res.Merged.WeakenedByWorkspace()...)
	return res, nil
}

// applyFile loads one TOML file into a layer.
func applyFile(res *Result, path, layerName string, apply func(map[string]any, string) error) error {
	if !fileExists(path) {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("reading %s: %w", abs, err)
	}
	tree, err := parseTOML(data)
	if err != nil {
		return &SchemaError{Layer: abs, Errors: []error{err}}
	}
	if layerName == LayerWorkspace {
		res.WorkspaceFile = abs
	}
	// Record the backing file path in the origin for file-backed layers, so a
	// relative [image].dockerfile can be resolved against the file that set
	// it.
	return apply(tree, layerName+":"+abs)
}

// layerFileDir returns the directory of the config file behind an origin
// attribution, or "" when the layer is not backed by a file. File-backed
// layers are recorded as "<layer>:<abs path>".
func layerFileDir(origin string) string {
	if i := strings.IndexByte(origin, ':'); i >= 0 {
		if p := origin[i+1:]; filepath.IsAbs(p) {
			return filepath.Dir(p)
		}
	}
	return ""
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
