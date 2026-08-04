package share

import (
	"bytes"
	"testing"
)

// The FUSE wire ABI is fixed-layout; a struct drifting in size would
// corrupt every exchange after it. Pin the sizes the kernel expects at
// protocol 7.31.
func TestWireStructSizes(t *testing.T) {
	sizes := []struct {
		name string
		v    any
		want int
	}{
		{"inHeader", &inHeader{}, 40},
		{"outHeader", &outHeader{}, 16},
		{"fuseAttr", &fuseAttr{}, 88},
		{"entryOut", &entryOut{}, 128},
		{"attrOut", &attrOut{}, 104},
		{"initOut", &initOut{}, 64},
		{"openOut", &openOut{}, 16},
		{"writeOut", &writeOut{}, 8},
		{"kstatfs", &kstatfs{}, 80},
		{"setattrIn", &setattrIn{}, 88},
		{"readIn", &readIn{}, 40},
		{"writeIn", &writeIn{}, 40},
		{"releaseIn", &releaseIn{}, 24},
		{"dirent", &dirent{}, direntSize},
		{"lseekOut", &lseekOut{}, 8},
	}
	for _, s := range sizes {
		var buf bytes.Buffer
		encode(&buf, s.v)
		if buf.Len() != s.want {
			t.Errorf("%s encodes to %d bytes, want %d", s.name, buf.Len(), s.want)
		}
	}
}

func TestParseName(t *testing.T) {
	name, rest, err := parseName([]byte("hello\x00world\x00"))
	if err != nil || name != "hello" || string(rest) != "world\x00" {
		t.Errorf("parseName = %q %q %v", name, rest, err)
	}
	if _, _, err := parseName([]byte("unterminated")); err == nil {
		t.Error("unterminated name must error")
	}
}

func TestDirentAlign(t *testing.T) {
	for in, want := range map[int]int{0: 0, 1: 8, 8: 8, 9: 16, 24: 24, 25: 32} {
		if got := direntAlign(in); got != want {
			t.Errorf("direntAlign(%d) = %d, want %d", in, got, want)
		}
	}
}
