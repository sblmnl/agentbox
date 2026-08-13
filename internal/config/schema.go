package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Scope classifies every configuration key. Backend-specific keys are
// legal only inside their scoped table; anywhere else they are a schema
// error on every machine, regardless of the active backend.
type Scope int

const (
	ScopeNeutral Scope = iota
	ScopeContainer
	ScopeVM
)

type kind int

const (
	kString kind = iota
	kBool
	kInt
	kFloat
	kStringList
	kStringMap // table of string -> string
	kDuration  // "30m", "1h", "0"
	kSize      // "8g", "512m"
	kNumber    // int or float (resources.cpus)
	kCommand   // list of strings (argv)
)

type keySpec struct {
	kind kind
	enum []string // non-empty: value must be one of these
}

// schema maps dotted key paths to their spec. A "*" component matches any
// single key (open key sets: toolchains, variables).
var schema = map[string]keySpec{
	"version": {kind: kInt},

	"box.default_command": {kind: kCommand},
	"box.idle_timeout":    {kind: kDuration},

	"workspace.mount":    {kind: kString},
	"workspace.readonly": {kind: kBool},

	"toolchains.*": {kind: kString},

	"image.ref":        {kind: kString},
	"image.base":       {kind: kString},
	"image.dockerfile": {kind: kString},
	"image.packages":   {kind: kStringList},
	"image.build_args": {kind: kStringMap},

	"agents.install": {kind: kStringList},
	"agents.channel": {kind: kString, enum: []string{"stable", "latest"}},

	"network.mode":                  {kind: kString, enum: []string{"off", "proxy", "open"}},
	"network.bundles":               {kind: kStringList},
	"network.allow":                 {kind: kStringList},
	"network.deny":                  {kind: kStringList},
	"network.audit":                 {kind: kBool},
	"network.proxy.read_timeout":    {kind: kDuration},
	"network.proxy.request_timeout": {kind: kDuration},

	"resources.memory":     {kind: kSize},
	"resources.cpus":       {kind: kNumber},
	"resources.pids":       {kind: kInt},
	"resources.tmpfs_size": {kind: kSize},
	"resources.nofile":     {kind: kInt},

	"security.min_isolation": {kind: kString, enum: []string{"container", "vm"}},
	"security.backend":       {kind: kString, enum: []string{"container", "vm"}},
	"security.strip_setuid":  {kind: kBool},
	"security.mask_mode":     {kind: kString, enum: []string{"auto", "view", "filter"}},

	"security.container.read_only_root":    {kind: kBool},
	"security.container.no_new_privileges": {kind: kBool},
	"security.container.cap_drop":          {kind: kStringList},
	"security.container.cap_add":           {kind: kStringList},
	"security.container.userns":            {kind: kString, enum: []string{"auto", "keep-id", "host", "off"}},
	"security.container.seccomp":           {kind: kString},

	// The vm tier is Kata via a container engine. There is no hypervisor or
	// runtime key: offering a choice agentbox cannot honor is how the krun
	// mess happened -- a value that parsed, selected, created a box, and then
	// could not be entered.
	"security.vm.guest_root":     {kind: kString, enum: []string{"allow", "deny"}},
	"security.vm.nested_docker":  {kind: kBool},
	"security.vm.memory_backing": {kind: kString, enum: []string{"balloon", "prealloc"}},

	"masking.ignore_files":   {kind: kStringList},
	"masking.tmpfs_size":     {kind: kSize},
	"masking.files_readonly": {kind: kBool},

	"variables.*":                 {kind: kString},
	"variables.passthrough.names": {kind: kStringList},
}

// scopedLeafOwner maps a bare backend-specific key name to the scoped table
// it belongs in, so misplacement produces a scope error naming the fix
// rather than a generic unknown-key error.
var scopedLeafOwner = map[string]string{
	"read_only_root":    "security.container",
	"no_new_privileges": "security.container",
	"cap_drop":          "security.container",
	"cap_add":           "security.container",
	"userns":            "security.container",
	"seccomp":           "security.container",
	"nested_docker":     "security.vm",
	"memory_backing":    "security.vm",
	"guest_root":        "security.vm",
}

// KeyScope returns the scope of a dotted key path.
func KeyScope(path string) Scope {
	switch {
	case strings.HasPrefix(path, "security.container."):
		return ScopeContainer
	case strings.HasPrefix(path, "security.vm."):
		return ScopeVM
	}
	return ScopeNeutral
}

func lookupSpec(path string) (keySpec, bool) {
	if s, ok := schema[path]; ok {
		return s, true
	}
	// Wildcard: replace the final component with "*".
	if i := strings.LastIndex(path, "."); i > 0 {
		if s, ok := schema[path[:i]+".*"]; ok {
			return s, true
		}
	}
	return keySpec{}, false
}

var durRe = regexp.MustCompile(`^(0|([0-9]+h)?([0-9]+m)?([0-9]+s)?)$`)
var sizeRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[kmgtKMGT]?[bB]?$`)

// ValidateValue checks a scalar/list value against its spec.
func (s keySpec) validate(path string, v any) error {
	bad := func(want string) error {
		return fmt.Errorf("%s: expected %s, got %T", path, want, v)
	}
	switch s.kind {
	case kString, kDuration, kSize:
		str, ok := v.(string)
		if !ok {
			return bad("string")
		}
		if s.kind == kDuration && !durRe.MatchString(str) {
			return fmt.Errorf("%s: invalid duration %q (use forms like \"30m\", \"1h30m\", \"0\")", path, str)
		}
		if s.kind == kSize && !sizeRe.MatchString(str) {
			return fmt.Errorf("%s: invalid size %q (use forms like \"8g\", \"512m\")", path, str)
		}
		if len(s.enum) > 0 {
			for _, e := range s.enum {
				if str == e {
					return nil
				}
			}
			return fmt.Errorf("%s: invalid value %q (one of: %s)", path, str, strings.Join(s.enum, ", "))
		}
	case kBool:
		if _, ok := v.(bool); !ok {
			return bad("boolean")
		}
	case kInt:
		switch v.(type) {
		case int64, int:
		default:
			return bad("integer")
		}
	case kFloat, kNumber:
		switch v.(type) {
		case int64, int, float64:
		default:
			return bad("number")
		}
	case kStringList, kCommand:
		list, ok := v.([]any)
		if !ok {
			return bad("array of strings")
		}
		for _, el := range list {
			if _, ok := el.(string); !ok {
				return fmt.Errorf("%s: array elements must be strings, got %T", path, el)
			}
		}
	case kStringMap:
		m, ok := v.(map[string]any)
		if !ok {
			return bad("table of strings")
		}
		for k, el := range m {
			if _, ok := el.(string); !ok {
				return fmt.Errorf("%s.%s: expected string, got %T", path, k, el)
			}
		}
	}
	return nil
}

// ValidateTree walks a raw decoded TOML tree and returns every schema error:
// unknown keys (hard errors), type errors, enum violations, and
// backend-scope violations with a message naming the correct location.
func ValidateTree(tree map[string]any) []error {
	var errs []error
	walkTree(tree, "", &errs)
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return errs
}

func walkTree(tree map[string]any, prefix string, errs *[]error) {
	for k, v := range tree {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}

		if spec, ok := lookupSpec(path); ok {
			if err := spec.validate(path, v); err != nil {
				*errs = append(*errs, err)
			}
			continue
		}

		// Not a known leaf. Descend if it is a table with known children.
		if sub, ok := v.(map[string]any); ok && hasSchemaUnder(path) {
			walkTree(sub, path, errs)
			continue
		}

		// Unknown key. Distinguish a scope violation from a typo.
		leaf := k
		if owner, scoped := scopedLeafOwner[leaf]; scoped {
			*errs = append(*errs, fmt.Errorf(
				"%s: backend-scoped key %q is not valid here; it belongs under [%s] (backend scope is validated statically on every machine)",
				path, leaf, owner))
			continue
		}
		*errs = append(*errs, fmt.Errorf("%s: unknown key (unknown keys are a hard error; a silently ignored key is a security bug)", path))
	}
}

// hasSchemaUnder reports whether any schema path is nested under prefix.
func hasSchemaUnder(prefix string) bool {
	p := prefix + "."
	for k := range schema {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}
