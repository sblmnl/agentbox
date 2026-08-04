package config

import (
	"sort"
	"strings"
)

// Merge semantics: scalar values replace; tables merge key-wise so a
// higher layer setting one key does not discard its siblings; arrays append,
// with two escapes:
//
//	"!reset"  discards everything inherited so far for that key
//	"!value"  removes an inherited element equal to "value"
//
// Origin tracking records, per dotted key, the name of the layer that
// supplied the final value (`config --origin`).

type Merged struct {
	Tree   map[string]any
	Origin map[string]string // dotted key -> layer name
}

func NewMerged() *Merged {
	return &Merged{Tree: map[string]any{}, Origin: map[string]string{}}
}

// Apply merges layer (already schema-validated) into m, attributing values
// to layerName.
func (m *Merged) Apply(tree map[string]any, layerName string) {
	mergeTables(m.Tree, tree, "", layerName, m.Origin)
}

func mergeTables(dst, src map[string]any, prefix, layer string, origin map[string]string) {
	for k, v := range src {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		switch sv := v.(type) {
		case map[string]any:
			if dv, ok := dst[k].(map[string]any); ok {
				mergeTables(dv, sv, path, layer, origin)
			} else {
				fresh := map[string]any{}
				mergeTables(fresh, sv, path, layer, origin)
				dst[k] = fresh
			}
		case []any:
			prev, _ := dst[k].([]any)
			merged, contributed := mergeArrays(prev, sv)
			dst[k] = merged
			if contributed {
				origin[path] = layer
			} else if _, seen := origin[path]; !seen {
				origin[path] = layer
			} else {
				// Array unchanged by this layer; keep prior attribution but
				// note the append chain.
				origin[path] = origin[path] + "," + layer
			}
		case []map[string]any:
			// Array of tables ([[workspace.mounts]]): append, no escapes.
			prev, _ := dst[k].([]map[string]any)
			dst[k] = append(prev, sv...)
			origin[path] = layer
		default:
			dst[k] = v
			origin[path] = layer
		}
	}
}

// mergeArrays applies append-with-escapes. It returns the merged array and
// whether src actually changed the result.
func mergeArrays(inherited, src []any) ([]any, bool) {
	out := append([]any{}, inherited...)
	changed := len(src) > 0
	for _, el := range src {
		s, ok := el.(string)
		if ok && s == "!reset" {
			out = out[:0]
			continue
		}
		if ok && strings.HasPrefix(s, "!") {
			needle := s[1:]
			kept := out[:0]
			for _, e := range out {
				if es, ok := e.(string); ok && es == needle {
					continue
				}
				kept = append(kept, e)
			}
			out = kept
			continue
		}
		out = append(out, el)
	}
	return out, changed
}

// FlattenOrigins returns sorted "key = value  (layer)" rows for --origin.
func (m *Merged) FlattenOrigins() []string {
	keys := make([]string, 0, len(m.Origin))
	for k := range m.Origin {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Lookup returns the value at a dotted path, or nil.
func (m *Merged) Lookup(path string) any {
	parts := strings.Split(path, ".")
	cur := any(m.Tree)
	for _, p := range parts {
		t, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = t[p]
	}
	return cur
}
