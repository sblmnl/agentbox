//go:build linux

package share

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/sblmnl/agentbox/internal/ignore"
	"github.com/sblmnl/agentbox/internal/mask"
)

// The tests here drive the real Serve loop over a socketpair, speaking the
// FUSE wire protocol exactly as the kernel does over /dev/fuse. That
// exercises every filter-mode guarantee — ENOENT at lookup, omission from
// listings, EPERM on writes to masked names, and the dynamic behavior view
// mode cannot deliver — without needing root or a mount, which is what CI
// runs. TestFilterRealMount (privileged) covers the same semantics through
// an actual kernel mount.

type harness struct {
	t      *testing.T
	kern   *os.File
	root   string
	unique uint64
}

func newHarness(t *testing.T, patterns string, files map[string]string) *harness {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := &ignore.Matcher{}
	if err := m.AddFile(strings.NewReader(patterns), ".agentignore"); err != nil {
		t.Fatal(err)
	}
	fs, err := NewFS(root, Filter(mask.FilterFn(m)), m.HasAnchored())
	if err != nil {
		t.Fatal(err)
	}

	// SOCK_SEQPACKET preserves the one-message-per-read framing /dev/fuse
	// provides.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	kern := os.NewFile(uintptr(fds[0]), "fuse-kernel-side")
	daemon := os.NewFile(uintptr(fds[1]), "fuse-daemon-side")
	go func() {
		defer fs.Close()
		_ = NewConn(daemon, fs).Serve()
	}()
	t.Cleanup(func() { kern.Close(); daemon.Close() })

	h := &harness{t: t, kern: kern, root: root}
	h.init()
	return h
}

func (h *harness) send(opcode uint32, nodeid uint64, body []byte) uint64 {
	h.t.Helper()
	h.unique++
	var buf bytes.Buffer
	encode(&buf, &inHeader{
		Len:    uint32(inHeaderSize + len(body)),
		Opcode: opcode,
		Unique: h.unique,
		Nodeid: nodeid,
	})
	buf.Write(body)
	if _, err := h.kern.Write(buf.Bytes()); err != nil {
		h.t.Fatalf("writing request opcode %d: %v", opcode, err)
	}
	return h.unique
}

// roundtrip sends one request and reads its reply, returning the negated
// errno (as a positive syscall.Errno; 0 on success) and the payload.
func (h *harness) roundtrip(opcode uint32, nodeid uint64, body []byte) (syscall.Errno, []byte) {
	h.t.Helper()
	unique := h.send(opcode, nodeid, body)
	buf := make([]byte, bufSize)
	n, err := h.kern.Read(buf)
	if err != nil {
		h.t.Fatalf("reading reply for opcode %d: %v", opcode, err)
	}
	var hdr outHeader
	if err := decode(buf[:outHeaderSize], &hdr); err != nil {
		h.t.Fatal(err)
	}
	if hdr.Unique != unique {
		h.t.Fatalf("reply unique %d, want %d", hdr.Unique, unique)
	}
	return syscall.Errno(-hdr.Error), buf[outHeaderSize:n]
}

func (h *harness) init() {
	h.t.Helper()
	var body bytes.Buffer
	encode(&body, &initIn{Major: protoMajor, Minor: 43, MaxReadahead: 65536, Flags: 0xffff_ffff})
	errno, payload := h.roundtrip(opInit, 0, body.Bytes())
	if errno != 0 {
		h.t.Fatalf("INIT failed: %v", errno)
	}
	var out initOut
	if err := decode(payload, &out); err != nil {
		h.t.Fatal(err)
	}
	if out.Major != protoMajor || out.Minor != protoMinor {
		h.t.Fatalf("negotiated %d.%d, want %d.%d", out.Major, out.Minor, protoMajor, protoMinor)
	}
	if out.MaxWrite != maxWrite {
		h.t.Fatalf("max_write %d, want %d", out.MaxWrite, maxWrite)
	}
}

func nameBody(prefix []byte, names ...string) []byte {
	out := append([]byte{}, prefix...)
	for _, n := range names {
		out = append(out, n...)
		out = append(out, 0)
	}
	return out
}

func (h *harness) lookup(parent uint64, name string) (syscall.Errno, entryOut) {
	h.t.Helper()
	errno, payload := h.roundtrip(opLookup, parent, nameBody(nil, name))
	var out entryOut
	if errno == 0 {
		if err := decode(payload, &out); err != nil {
			h.t.Fatal(err)
		}
	}
	return errno, out
}

// readdirNames opens the directory, reads every entry name, and releases.
func (h *harness) readdirNames(nodeid uint64) []string {
	h.t.Helper()
	errno, payload := h.roundtrip(opOpendir, nodeid, make([]byte, 8))
	if errno != 0 {
		h.t.Fatalf("OPENDIR: %v", errno)
	}
	var open openOut
	if err := decode(payload, &open); err != nil {
		h.t.Fatal(err)
	}

	var names []string
	offset := uint64(0)
	for {
		var body bytes.Buffer
		encode(&body, &readIn{Fh: open.Fh, Offset: offset, Size: 8192})
		errno, payload := h.roundtrip(opReaddir, nodeid, body.Bytes())
		if errno != 0 {
			h.t.Fatalf("READDIR: %v", errno)
		}
		if len(payload) == 0 {
			break
		}
		for len(payload) >= direntSize {
			var d dirent
			if err := decode(payload[:direntSize], &d); err != nil {
				h.t.Fatal(err)
			}
			names = append(names, string(payload[direntSize:direntSize+int(d.Namelen)]))
			offset = d.Off
			payload = payload[direntAlign(direntSize+int(d.Namelen)):]
		}
	}

	var rel bytes.Buffer
	encode(&rel, &releaseIn{Fh: open.Fh})
	if errno, _ := h.roundtrip(opReleasedir, nodeid, rel.Bytes()); errno != 0 {
		h.t.Fatalf("RELEASEDIR: %v", errno)
	}
	return names
}

func contains(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

const testPatterns = ".env\n*.pem\nsecrets/\nb/hidden.txt\n"

func testTree() map[string]string {
	return map[string]string{
		"main.go":             "package main\n",
		".env":                "SECRET=1",
		"secrets/token":       "tok",
		"a/hidden.txt":        "will be masked after rename",
		"a/visible.txt":       "stays visible",
		"docs/readme.md":      "docs",
		"docs/dev-key.pem":    "PRIVATE KEY",
		"docs/config.example": "example",
	}
}

func TestLookupMaskedIsENOENT(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())

	if errno, _ := h.lookup(rootNodeID, ".env"); errno != syscall.ENOENT {
		t.Errorf("LOOKUP .env = %v, want ENOENT", errno)
	}
	if errno, _ := h.lookup(rootNodeID, "secrets"); errno != syscall.ENOENT {
		t.Errorf("LOOKUP secrets = %v, want ENOENT (masked directory)", errno)
	}
	errno, entry := h.lookup(rootNodeID, "main.go")
	if errno != 0 {
		t.Fatalf("LOOKUP main.go = %v, want success", errno)
	}
	if entry.Attr.Mode&syscall.S_IFMT != syscall.S_IFREG {
		t.Errorf("main.go mode %o, want regular file", entry.Attr.Mode)
	}
	if entry.Attr.Size != uint64(len("package main\n")) {
		t.Errorf("main.go size %d", entry.Attr.Size)
	}

	// A masked name in a subdirectory, matched by a *.pem glob.
	errno, docs := h.lookup(rootNodeID, "docs")
	if errno != 0 {
		t.Fatal(errno)
	}
	if errno, _ := h.lookup(docs.Nodeid, "dev-key.pem"); errno != syscall.ENOENT {
		t.Errorf("LOOKUP docs/dev-key.pem = %v, want ENOENT", errno)
	}
	if errno, _ := h.lookup(docs.Nodeid, "readme.md"); errno != 0 {
		t.Errorf("LOOKUP docs/readme.md = %v, want success", errno)
	}
}

func TestReaddirOmitsMasked(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())
	names := h.readdirNames(rootNodeID)

	for _, want := range []string{".", "..", "main.go", "a", "docs"} {
		if !contains(names, want) {
			t.Errorf("listing must include %q, got %v", want, names)
		}
	}
	for _, banned := range []string{".env", "secrets"} {
		if contains(names, banned) {
			t.Errorf("listing must omit masked %q, got %v", banned, names)
		}
	}
}

// TestDynamicMasking is the filter-mode guarantee view mode cannot deliver: a
// file created after the share is up, matching a pattern, is masked.
func TestDynamicMasking(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())

	// Mid-session, the host tree gains a matching file (as it would when
	// the agent, or anything else, writes one).
	if err := os.WriteFile(filepath.Join(h.root, "fresh-key.pem"), []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "fresh-notes.md"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}

	if errno, _ := h.lookup(rootNodeID, "fresh-key.pem"); errno != syscall.ENOENT {
		t.Errorf("mid-session .pem: LOOKUP = %v, want ENOENT", errno)
	}
	if errno, _ := h.lookup(rootNodeID, "fresh-notes.md"); errno != 0 {
		t.Errorf("mid-session unmasked file: LOOKUP = %v, want success", errno)
	}
	names := h.readdirNames(rootNodeID)
	if contains(names, "fresh-key.pem") {
		t.Errorf("mid-session .pem must be omitted from listing, got %v", names)
	}
	if !contains(names, "fresh-notes.md") {
		t.Errorf("mid-session unmasked file must be listed, got %v", names)
	}
}

func TestCreateFamilyRefusesMaskedNames(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())

	var create bytes.Buffer
	encode(&create, &createIn{Flags: uint32(os.O_RDWR), Mode: 0o644})
	errno, _ := h.roundtrip(opCreate, rootNodeID, nameBody(create.Bytes(), ".env"))
	if errno != syscall.EPERM {
		t.Errorf("CREATE .env = %v, want EPERM", errno)
	}

	var mkdir bytes.Buffer
	encode(&mkdir, &mkdirIn{Mode: 0o755})
	errno, _ = h.roundtrip(opMkdir, rootNodeID, nameBody(mkdir.Bytes(), "secrets"))
	if errno != syscall.EPERM {
		t.Errorf("MKDIR secrets = %v, want EPERM", errno)
	}

	errno, _ = h.roundtrip(opSymlink, rootNodeID, nameBody(nil, "leak.pem", "main.go"))
	if errno != syscall.EPERM {
		t.Errorf("SYMLINK leak.pem = %v, want EPERM", errno)
	}

	// Renaming a visible file onto a masked name must refuse too.
	var ren bytes.Buffer
	encode(&ren, &renameIn{Newdir: rootNodeID})
	errno, _ = h.roundtrip(opRename, rootNodeID, nameBody(ren.Bytes(), "main.go", ".env"))
	if errno != syscall.EPERM {
		t.Errorf("RENAME main.go -> .env = %v, want EPERM", errno)
	}
	// ...and the EPERMs must not have touched the host tree.
	if _, err := os.Stat(filepath.Join(h.root, "main.go")); err != nil {
		t.Errorf("main.go must be untouched after refused rename: %v", err)
	}
	for _, p := range []string{"leak.pem"} {
		if _, err := os.Lstat(filepath.Join(h.root, p)); !os.IsNotExist(err) {
			t.Errorf("%s must not exist on the host after refusal", p)
		}
	}
}

func TestRemoveMaskedIsENOENT(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())

	errno, _ := h.roundtrip(opUnlink, rootNodeID, nameBody(nil, ".env"))
	if errno != syscall.ENOENT {
		t.Errorf("UNLINK .env = %v, want ENOENT", errno)
	}
	errno, _ = h.roundtrip(opRmdir, rootNodeID, nameBody(nil, "secrets"))
	if errno != syscall.ENOENT {
		t.Errorf("RMDIR secrets = %v, want ENOENT", errno)
	}
	// The host files must survive the refused removals.
	if _, err := os.Stat(filepath.Join(h.root, ".env")); err != nil {
		t.Errorf(".env must survive on the host: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "secrets", "token")); err != nil {
		t.Errorf("secrets/token must survive on the host: %v", err)
	}
}

// TestRenameTracksRelPaths: the filter evaluates workspace-relative paths,
// so moving a directory under a name a pattern anchors to must mask its
// matching children from that moment on.
func TestRenameTracksRelPaths(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())

	errno, a := h.lookup(rootNodeID, "a")
	if errno != 0 {
		t.Fatal(errno)
	}
	if errno, _ := h.lookup(a.Nodeid, "hidden.txt"); errno != 0 {
		t.Fatalf("a/hidden.txt must be visible before the rename, got %v", errno)
	}

	var ren bytes.Buffer
	encode(&ren, &renameIn{Newdir: rootNodeID})
	if errno, _ := h.roundtrip(opRename, rootNodeID, nameBody(ren.Bytes(), "a", "b")); errno != 0 {
		t.Fatalf("RENAME a -> b: %v", errno)
	}

	// Same directory node, resolved through its new name: the pattern
	// "b/hidden.txt" now applies.
	if errno, _ := h.lookup(a.Nodeid, "hidden.txt"); errno != syscall.ENOENT {
		t.Errorf("b/hidden.txt after rename = %v, want ENOENT", errno)
	}
	if errno, _ := h.lookup(a.Nodeid, "visible.txt"); errno != 0 {
		t.Errorf("b/visible.txt must stay visible, got %v", errno)
	}
	names := h.readdirNames(a.Nodeid)
	if contains(names, "hidden.txt") {
		t.Errorf("listing of b must omit hidden.txt, got %v", names)
	}
}

// TestRenameRefusedWhenSubtreeHidesMasked is the counterpart to
// TestRenameTracksRelPaths: a directory that currently hides a masked entry
// may not be renamed, because an anchored pattern would no longer match the
// entry at its new path. View mode blocks the same move with EBUSY (the
// masked path is a live mountpoint), and filter mode must not be weaker.
func TestRenameRefusedWhenSubtreeHidesMasked(t *testing.T) {
	h := newHarness(t, testPatterns, map[string]string{
		"b/hidden.txt":  "secret",
		"b/visible.txt": "ok",
	})

	// b/hidden.txt is masked by the anchored pattern "b/hidden.txt".
	errno, b := h.lookup(rootNodeID, "b")
	if errno != 0 {
		t.Fatal(errno)
	}
	if errno, _ := h.lookup(b.Nodeid, "hidden.txt"); errno != syscall.ENOENT {
		t.Fatalf("b/hidden.txt must be masked, got %v", errno)
	}

	// Renaming b (which hides b/hidden.txt) to c would expose c/hidden.txt.
	var ren bytes.Buffer
	encode(&ren, &renameIn{Newdir: rootNodeID})
	if errno, _ := h.roundtrip(opRename, rootNodeID, nameBody(ren.Bytes(), "b", "c")); errno != syscall.EBUSY {
		t.Fatalf("RENAME b -> c = %v, want EBUSY", errno)
	}

	// The host tree is untouched and the file stays masked.
	if _, err := os.Stat(filepath.Join(h.root, "b", "hidden.txt")); err != nil {
		t.Errorf("b/hidden.txt must survive the refused rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "c")); !os.IsNotExist(err) {
		t.Errorf("c must not exist after the refused rename")
	}
	if errno, _ := h.lookup(b.Nodeid, "hidden.txt"); errno != syscall.ENOENT {
		t.Errorf("b/hidden.txt must stay masked after the refusal, got %v", errno)
	}
}

// TestRenameAllowedForUnanchoredPatterns: with no anchored rule the subtree
// walk is skipped — unanchored patterns match by basename and survive an
// ancestor rename — so the rename proceeds without weakening the mask.
func TestRenameAllowedForUnanchoredPatterns(t *testing.T) {
	h := newHarness(t, ".env\n", map[string]string{
		"sub/.env":     "SECRET=1",
		"sub/keep.txt": "ok",
	})

	errno, sub := h.lookup(rootNodeID, "sub")
	if errno != 0 {
		t.Fatal(errno)
	}
	if errno, _ := h.lookup(sub.Nodeid, ".env"); errno != syscall.ENOENT {
		t.Fatalf("sub/.env must be masked, got %v", errno)
	}

	var ren bytes.Buffer
	encode(&ren, &renameIn{Newdir: rootNodeID})
	if errno, _ := h.roundtrip(opRename, rootNodeID, nameBody(ren.Bytes(), "sub", "moved")); errno != 0 {
		t.Fatalf("RENAME sub -> moved (unanchored patterns) = %v, want success", errno)
	}
	// The basename pattern still masks .env at the new location.
	if errno, _ := h.lookup(sub.Nodeid, ".env"); errno != syscall.ENOENT {
		t.Errorf("moved/.env must stay masked, got %v", errno)
	}
	if errno, _ := h.lookup(sub.Nodeid, "keep.txt"); errno != 0 {
		t.Errorf("moved/keep.txt must stay visible, got %v", errno)
	}
}

func TestWriteReadRoundtrip(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())

	var create bytes.Buffer
	encode(&create, &createIn{Flags: uint32(os.O_RDWR), Mode: 0o644})
	errno, payload := h.roundtrip(opCreate, rootNodeID, nameBody(create.Bytes(), "notes.txt"))
	if errno != 0 {
		t.Fatalf("CREATE notes.txt: %v", errno)
	}
	var entry entryOut
	var open openOut
	if err := decode(payload[:binarySize(&entry)], &entry); err != nil {
		t.Fatal(err)
	}
	if err := decode(payload[binarySize(&entry):], &open); err != nil {
		t.Fatal(err)
	}

	content := []byte("hello through the filtered share\n")
	var w bytes.Buffer
	encode(&w, &writeIn{Fh: open.Fh, Offset: 0, Size: uint32(len(content))})
	w.Write(content)
	errno, payload = h.roundtrip(opWrite, entry.Nodeid, w.Bytes())
	if errno != 0 {
		t.Fatalf("WRITE: %v", errno)
	}
	var wout writeOut
	if err := decode(payload, &wout); err != nil {
		t.Fatal(err)
	}
	if wout.Size != uint32(len(content)) {
		t.Fatalf("wrote %d, want %d", wout.Size, len(content))
	}

	var r bytes.Buffer
	encode(&r, &readIn{Fh: open.Fh, Offset: 0, Size: 4096})
	errno, payload = h.roundtrip(opRead, entry.Nodeid, r.Bytes())
	if errno != 0 || !bytes.Equal(payload, content) {
		t.Fatalf("READ = %v %q, want %q", errno, payload, content)
	}

	var rel bytes.Buffer
	encode(&rel, &releaseIn{Fh: open.Fh})
	if errno, _ := h.roundtrip(opRelease, entry.Nodeid, rel.Bytes()); errno != 0 {
		t.Fatalf("RELEASE: %v", errno)
	}

	// The write reached the host tree (an unmasked path passes through).
	got, err := os.ReadFile(filepath.Join(h.root, "notes.txt"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("host content %q (%v), want %q", got, err, content)
	}
}

func TestSetattrTruncateAndGetattr(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())

	errno, entry := h.lookup(rootNodeID, "main.go")
	if errno != 0 {
		t.Fatal(errno)
	}
	var sa bytes.Buffer
	encode(&sa, &setattrIn{Valid: fattrSize, Size: 4})
	errno, payload := h.roundtrip(opSetattr, entry.Nodeid, sa.Bytes())
	if errno != 0 {
		t.Fatalf("SETATTR size: %v", errno)
	}
	var out attrOut
	if err := decode(payload, &out); err != nil {
		t.Fatal(err)
	}
	if out.Attr.Size != 4 {
		t.Errorf("size after truncate %d, want 4", out.Attr.Size)
	}
	if data, _ := os.ReadFile(filepath.Join(h.root, "main.go")); string(data) != "pack" {
		t.Errorf("host content after truncate: %q", data)
	}
}

func TestReadlinkAndSymlinkVisible(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())

	if err := os.Symlink("docs/readme.md", filepath.Join(h.root, "link.md")); err != nil {
		t.Fatal(err)
	}
	errno, entry := h.lookup(rootNodeID, "link.md")
	if errno != 0 {
		t.Fatalf("LOOKUP link.md: %v", errno)
	}
	if entry.Attr.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		t.Fatalf("mode %o, want symlink", entry.Attr.Mode)
	}
	errno, payload := h.roundtrip(opReadlink, entry.Nodeid, nil)
	if errno != 0 || string(payload) != "docs/readme.md" {
		t.Fatalf("READLINK = %v %q", errno, payload)
	}
}

// A symlink whose *name* matches a pattern is masked like a file — the
// same rule Layer 0 applies ("symlinks MUST be masked as files").
func TestSymlinkNameMasked(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())
	if err := os.Symlink("main.go", filepath.Join(h.root, "alias.pem")); err != nil {
		t.Fatal(err)
	}
	if errno, _ := h.lookup(rootNodeID, "alias.pem"); errno != syscall.ENOENT {
		t.Errorf("LOOKUP alias.pem (symlink) = %v, want ENOENT", errno)
	}
}

func TestUnknownOpcodeIsENOSYS(t *testing.T) {
	h := newHarness(t, testPatterns, testTree())
	errno, _ := h.roundtrip(9999, rootNodeID, nil)
	if errno != syscall.ENOSYS {
		t.Errorf("unknown opcode = %v, want ENOSYS", errno)
	}
	// The connection keeps serving afterwards.
	if errno, _ := h.lookup(rootNodeID, "main.go"); errno != 0 {
		t.Errorf("connection must survive an unknown opcode, got %v", errno)
	}
}

func binarySize(v any) int {
	var buf bytes.Buffer
	encode(&buf, v)
	return buf.Len()
}
