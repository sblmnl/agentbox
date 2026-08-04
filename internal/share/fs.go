//go:build linux

package share

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

// Filter is the Layer 3 lookup predicate (mask.FilterFn): whether the
// workspace-relative path must be reported ENOENT and omitted from
// directory listings. It is evaluated on every lookup and every directory
// read — that is what makes filter mode dynamic where view mode is frozen
// at creation.
type Filter func(rel string, isDir bool) bool

// Linux constants the syscall package does not export.
const (
	oPath             = 0x200000 // O_PATH
	atEmptyPath       = 0x1000   // AT_EMPTY_PATH
	atSymlinkNofollow = 0x100    // AT_SYMLINK_NOFOLLOW
	atSymlinkFollow   = 0x400    // AT_SYMLINK_FOLLOW
	atRemovedir       = 0x200    // AT_REMOVEDIR
	fdcwd             = -0x64    // AT_FDCWD

	dtUnknown = 0
	dtDir     = 4
)

// nodeKey identifies an inode across lookups so hard links and repeated
// lookups share one node (and one O_PATH fd).
type nodeKey struct {
	Dev uint64
	Ino uint64
}

// node is one kernel-visible inode. fd is an O_PATH pin of the inode: every
// operation is a single-component *at syscall relative to a pinned parent,
// so the daemon never re-resolves a multi-component path — symlink contents
// in the tree cannot redirect it outside the tree.
type node struct {
	id      uint64
	fd      int
	key     nodeKey
	parent  *node // nil only for the root
	name    string
	nlookup uint64
	isDir   bool
}

// handle is one open file or directory.
type handle struct {
	fd   int
	node *node
	// ents is the directory snapshot taken at OPENDIR, already filtered.
	// nil for file handles.
	ents []dirEntry
}

type dirEntry struct {
	name string
	ino  uint64
	typ  uint32
}

// FS is the filtering passthrough filesystem over one box tree.
type FS struct {
	mu      sync.Mutex
	nodes   map[uint64]*node
	byKey   map[nodeKey]*node
	nextID  uint64
	handles map[uint64]*handle
	nextFh  uint64
	filter  Filter
	root    *node
	// checkDirRename guards directory renames against relocating a masked
	// descendant onto a visible path. It is only needed when the pattern set
	// has anchored rules (paths with a '/'); unanchored rules match by
	// basename and are rename-invariant, so the walk is skipped when false.
	checkDirRename bool
}

// NewFS opens treeRoot and pins it as the mount root. The filter must be
// compiled from pattern contents frozen at daemon spawn: the daemon must
// never re-read pattern files from the guest-writable tree, or the agent
// could unmask paths by editing them. checkDirRename should be set when the
// compiled pattern set contains anchored rules (see (*ignore.Matcher).HasAnchored).
func NewFS(treeRoot string, filter Filter, checkDirRename bool) (*FS, error) {
	fd, err := syscall.Open(treeRoot, oPath|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", treeRoot, err)
	}
	var st syscall.Stat_t
	if err := fstatat(fd, "", &st, atEmptyPath); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("stat %s: %w", treeRoot, err)
	}
	root := &node{id: rootNodeID, fd: fd, key: keyOf(&st), nlookup: 1, isDir: true}
	return &FS{
		nodes:          map[uint64]*node{rootNodeID: root},
		byKey:          map[nodeKey]*node{root.key: root},
		nextID:         rootNodeID + 1,
		handles:        map[uint64]*handle{},
		nextFh:         1,
		filter:         filter,
		root:           root,
		checkDirRename: checkDirRename,
	}, nil
}

// Close releases every pinned inode and open handle.
func (f *FS) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nodes {
		syscall.Close(n.fd)
	}
	for _, h := range f.handles {
		syscall.Close(h.fd)
	}
	f.nodes, f.byKey, f.handles = map[uint64]*node{}, map[nodeKey]*node{}, map[uint64]*handle{}
}

func keyOf(st *syscall.Stat_t) nodeKey { return nodeKey{Dev: st.Dev, Ino: st.Ino} }

// rel is the '/'-separated workspace-relative path of n, "." for the root,
// computed by walking the parent chain so ancestor renames are reflected.
// Callers hold f.mu.
func (f *FS) rel(n *node) string {
	if n.parent == nil {
		return "."
	}
	segs := []string{}
	for cur := n; cur.parent != nil; cur = cur.parent {
		segs = append(segs, cur.name)
	}
	for i, j := 0, len(segs)-1; i < j; i, j = i+1, j-1 {
		segs[i], segs[j] = segs[j], segs[i]
	}
	return path.Join(segs...)
}

// relChild is the workspace-relative path of name under parent.
// Callers hold f.mu.
func (f *FS) relChild(parent *node, name string) string {
	if parent.parent == nil {
		return name
	}
	return f.rel(parent) + "/" + name
}

// masked evaluates the Layer 3 predicate for name under parent. The mount
// root itself is never subject to the filter. Callers hold f.mu.
func (f *FS) masked(parent *node, name string, isDir bool) bool {
	return f.filter(f.relChild(parent, name), isDir)
}

func (f *FS) maskedLocked(parent *node, name string, isDir bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.masked(parent, name, isDir)
}

// validName rejects path components the kernel should never send and that
// must never reach a syscall: empty, ".", "..", or anything containing a
// separator or NUL.
func validName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '/' || name[i] == 0 {
			return false
		}
	}
	return true
}

func errnoOf(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	if e, ok := err.(syscall.Errno); ok {
		return e
	}
	return syscall.EIO
}

// procPath names an fd's inode via /proc — the standard passthrough route
// for operations that need a real (non-O_PATH) handle or that lack an *at
// form. It resolves to the pinned inode, not a path in the tree, so the
// guest cannot redirect it.
func procPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

func (f *FS) getNode(id uint64) (*node, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[id]
	if !ok {
		return nil, syscall.ESTALE
	}
	return n, 0
}

func (f *FS) getHandle(fh uint64) (*handle, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.handles[fh]
	if !ok {
		return nil, syscall.EBADF
	}
	return h, 0
}

func (f *FS) newHandle(fd int, n *node, ents []dirEntry) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	fh := f.nextFh
	f.nextFh++
	f.handles[fh] = &handle{fd: fd, node: n, ents: ents}
	return fh
}

func attrFromStat(st *syscall.Stat_t) fuseAttr {
	return fuseAttr{
		Ino:       st.Ino,
		Size:      uint64(st.Size),
		Blocks:    uint64(st.Blocks),
		Atime:     uint64(st.Atim.Sec),
		Mtime:     uint64(st.Mtim.Sec),
		Ctime:     uint64(st.Ctim.Sec),
		AtimeNsec: uint32(st.Atim.Nsec),
		MtimeNsec: uint32(st.Mtim.Nsec),
		CtimeNsec: uint32(st.Ctim.Nsec),
		Mode:      st.Mode,
		Nlink:     uint32(st.Nlink),
		UID:       st.Uid,
		GID:       st.Gid,
		Rdev:      uint32(st.Rdev),
		Blksize:   uint32(st.Blksize),
	}
}

// attrTTL is the kernel attribute/entry cache budget in seconds. Negative
// lookups are never cached (masked paths answer plain ENOENT), so every
// name the guest resolves is re-filtered.
const attrTTL = 1

// pin stats name under parent, applies the filter, and returns a
// referenced node. The stat deciding the filter outcome is taken from the
// pinned fd itself, so a swap between stat and open cannot smuggle a
// masked file past the filter.
func (f *FS) pin(parent *node, name string) (*node, fuseAttr, syscall.Errno) {
	fd, err := syscall.Openat(parent.fd, name, oPath|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fuseAttr{}, errnoOf(err)
	}
	var st syscall.Stat_t
	if err := fstatat(fd, "", &st, atEmptyPath); err != nil {
		syscall.Close(fd)
		return nil, fuseAttr{}, errnoOf(err)
	}
	isDir := st.Mode&syscall.S_IFMT == syscall.S_IFDIR

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.masked(parent, name, isDir) {
		syscall.Close(fd)
		return nil, fuseAttr{}, syscall.ENOENT
	}
	key := keyOf(&st)
	if existing, ok := f.byKey[key]; ok {
		existing.nlookup++
		// The inode may have moved since first pinned; record the location
		// it was just resolved through so rel() stays current.
		existing.parent, existing.name = parent, name
		syscall.Close(fd)
		return existing, attrFromStat(&st), 0
	}
	n := &node{id: f.nextID, fd: fd, key: key, parent: parent, name: name, nlookup: 1, isDir: isDir}
	f.nextID++
	f.nodes[n.id] = n
	f.byKey[key] = n
	return n, attrFromStat(&st), 0
}

func entryFor(n *node, attr fuseAttr) entryOut {
	return entryOut{Nodeid: n.id, EntryValid: attrTTL, AttrValid: attrTTL, Attr: attr}
}

// Lookup answers LOOKUP: a masked name is ENOENT, by design
// indistinguishable from absence.
func (f *FS) Lookup(parentID uint64, name string) (entryOut, syscall.Errno) {
	parent, errno := f.getNode(parentID)
	if errno != 0 {
		return entryOut{}, errno
	}
	if !validName(name) {
		return entryOut{}, syscall.EINVAL
	}
	n, attr, errno := f.pin(parent, name)
	if errno != 0 {
		return entryOut{}, errno
	}
	return entryFor(n, attr), 0
}

// Forget drops kernel references; at zero the O_PATH pin is closed.
func (f *FS) Forget(nodeid, nlookup uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[nodeid]
	if !ok || n == f.root {
		return
	}
	if nlookup >= n.nlookup {
		n.nlookup = 0
	} else {
		n.nlookup -= nlookup
	}
	if n.nlookup == 0 {
		delete(f.nodes, n.id)
		delete(f.byKey, n.key)
		syscall.Close(n.fd)
	}
}

func (f *FS) Getattr(nodeid uint64) (attrOut, syscall.Errno) {
	n, errno := f.getNode(nodeid)
	if errno != 0 {
		return attrOut{}, errno
	}
	var st syscall.Stat_t
	if err := fstatat(n.fd, "", &st, atEmptyPath); err != nil {
		return attrOut{}, errnoOf(err)
	}
	return attrOut{AttrValid: attrTTL, Attr: attrFromStat(&st)}, 0
}

func (f *FS) Setattr(nodeid uint64, in *setattrIn) (attrOut, syscall.Errno) {
	n, errno := f.getNode(nodeid)
	if errno != 0 {
		return attrOut{}, errno
	}
	if in.Valid&fattrMode != 0 {
		if err := syscall.Chmod(procPath(n.fd), in.Mode&07777); err != nil {
			return attrOut{}, errnoOf(err)
		}
	}
	if in.Valid&(fattrUID|fattrGID) != 0 {
		uid, gid := -1, -1
		if in.Valid&fattrUID != 0 {
			uid = int(in.UID)
		}
		if in.Valid&fattrGID != 0 {
			gid = int(in.GID)
		}
		if err := syscall.Fchownat(n.fd, "", uid, gid, atEmptyPath); err != nil {
			return attrOut{}, errnoOf(err)
		}
	}
	if in.Valid&fattrSize != 0 {
		fd, err := syscall.Open(procPath(n.fd), syscall.O_WRONLY, 0)
		if err != nil {
			return attrOut{}, errnoOf(err)
		}
		err = syscall.Ftruncate(fd, int64(in.Size))
		syscall.Close(fd)
		if err != nil {
			return attrOut{}, errnoOf(err)
		}
	}
	if in.Valid&(fattrAtime|fattrMtime|fattrAtimeNow|fattrMtimeNow) != 0 {
		const utimeNow, utimeOmit = (1 << 30) - 1, (1 << 30) - 2
		ts := [2]syscall.Timespec{{Nsec: utimeOmit}, {Nsec: utimeOmit}}
		if in.Valid&fattrAtimeNow != 0 {
			ts[0] = syscall.Timespec{Nsec: utimeNow}
		} else if in.Valid&fattrAtime != 0 {
			ts[0] = syscall.Timespec{Sec: int64(in.Atime), Nsec: int64(in.AtimeNsec)}
		}
		if in.Valid&fattrMtimeNow != 0 {
			ts[1] = syscall.Timespec{Nsec: utimeNow}
		} else if in.Valid&fattrMtime != 0 {
			ts[1] = syscall.Timespec{Sec: int64(in.Mtime), Nsec: int64(in.MtimeNsec)}
		}
		// utimensat with a NULL path operates on the fd itself, which is
		// documented to work for O_PATH fds.
		if err := utimensatFd(n.fd, &ts); err != nil {
			return attrOut{}, errnoOf(err)
		}
	}
	return f.Getattr(nodeid)
}

func (f *FS) Readlink(nodeid uint64) ([]byte, syscall.Errno) {
	n, errno := f.getNode(nodeid)
	if errno != 0 {
		return nil, errno
	}
	// Empty path on an O_PATH|O_NOFOLLOW fd reads the pinned link itself.
	buf := make([]byte, 4096)
	sz, err := readlinkat(n.fd, "", buf)
	if err != nil {
		return nil, errnoOf(err)
	}
	return buf[:sz], 0
}

// The create-family guard: creating (or linking, or renaming onto) a name
// the filter would mask fails EPERM rather than producing a file that
// exists on the host while invisible to the guest — "writes to masked
// paths never reach the host", enforced loudly.

func (f *FS) Mknod(parentID uint64, name string, in *mknodIn) (entryOut, syscall.Errno) {
	parent, errno := f.getNode(parentID)
	if errno != 0 {
		return entryOut{}, errno
	}
	if !validName(name) {
		return entryOut{}, syscall.EINVAL
	}
	if f.maskedLocked(parent, name, false) {
		return entryOut{}, syscall.EPERM
	}
	if err := syscall.Mknodat(parent.fd, name, in.Mode, int(in.Rdev)); err != nil {
		return entryOut{}, errnoOf(err)
	}
	n, attr, errno := f.pin(parent, name)
	if errno != 0 {
		return entryOut{}, errno
	}
	return entryFor(n, attr), 0
}

func (f *FS) Mkdir(parentID uint64, name string, in *mkdirIn) (entryOut, syscall.Errno) {
	parent, errno := f.getNode(parentID)
	if errno != 0 {
		return entryOut{}, errno
	}
	if !validName(name) {
		return entryOut{}, syscall.EINVAL
	}
	if f.maskedLocked(parent, name, true) {
		return entryOut{}, syscall.EPERM
	}
	if err := syscall.Mkdirat(parent.fd, name, in.Mode); err != nil {
		return entryOut{}, errnoOf(err)
	}
	n, attr, errno := f.pin(parent, name)
	if errno != 0 {
		return entryOut{}, errno
	}
	return entryFor(n, attr), 0
}

func (f *FS) Symlink(parentID uint64, name, target string) (entryOut, syscall.Errno) {
	parent, errno := f.getNode(parentID)
	if errno != 0 {
		return entryOut{}, errno
	}
	if !validName(name) {
		return entryOut{}, syscall.EINVAL
	}
	if f.maskedLocked(parent, name, false) {
		return entryOut{}, syscall.EPERM
	}
	if err := symlinkat(target, parent.fd, name); err != nil {
		return entryOut{}, errnoOf(err)
	}
	n, attr, errno := f.pin(parent, name)
	if errno != 0 {
		return entryOut{}, errno
	}
	return entryFor(n, attr), 0
}

func (f *FS) Link(oldID, newParentID uint64, newName string) (entryOut, syscall.Errno) {
	old, errno := f.getNode(oldID)
	if errno != 0 {
		return entryOut{}, errno
	}
	parent, errno := f.getNode(newParentID)
	if errno != 0 {
		return entryOut{}, errno
	}
	if !validName(newName) {
		return entryOut{}, syscall.EINVAL
	}
	if f.maskedLocked(parent, newName, false) {
		return entryOut{}, syscall.EPERM
	}
	// AT_SYMLINK_FOLLOW through the /proc name of the pinned inode links
	// the inode itself; nothing inside the tree is resolved.
	if err := linkat(fdcwd, procPath(old.fd), parent.fd, newName, atSymlinkFollow); err != nil {
		return entryOut{}, errnoOf(err)
	}
	n, attr, errno := f.pin(parent, newName)
	if errno != 0 {
		return entryOut{}, errno
	}
	return entryFor(n, attr), 0
}

// remove implements UNLINK and RMDIR. A masked name answers ENOENT: it
// does not exist as far as the guest is concerned.
func (f *FS) remove(parentID uint64, name string, rmdir bool) syscall.Errno {
	parent, errno := f.getNode(parentID)
	if errno != 0 {
		return errno
	}
	if !validName(name) {
		return syscall.EINVAL
	}
	var st syscall.Stat_t
	if err := fstatat(parent.fd, name, &st, atSymlinkNofollow); err != nil {
		return errnoOf(err)
	}
	isDir := st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	if f.maskedLocked(parent, name, isDir) {
		return syscall.ENOENT
	}
	flags := 0
	if rmdir {
		flags = atRemovedir
	}
	return errnoOf(unlinkat(parent.fd, name, flags))
}

func (f *FS) Unlink(parentID uint64, name string) syscall.Errno {
	return f.remove(parentID, name, false)
}

func (f *FS) Rmdir(parentID uint64, name string) syscall.Errno {
	return f.remove(parentID, name, true)
}

const renameExchange = 2 // RENAME_EXCHANGE

// Rename reports a masked source as ENOENT and refuses (EPERM) to move a
// visible entry onto a masked name: the entry would land on the host
// while vanishing from the guest.
func (f *FS) Rename(parentID uint64, name string, newParentID uint64, newName string, flags uint32) syscall.Errno {
	parent, errno := f.getNode(parentID)
	if errno != 0 {
		return errno
	}
	newParent, errno := f.getNode(newParentID)
	if errno != 0 {
		return errno
	}
	if !validName(name) || !validName(newName) {
		return syscall.EINVAL
	}
	var st syscall.Stat_t
	if err := fstatat(parent.fd, name, &st, atSymlinkNofollow); err != nil {
		return errnoOf(err)
	}
	isDir := st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	if f.maskedLocked(parent, name, isDir) {
		return syscall.ENOENT
	}
	if f.maskedLocked(newParent, newName, isDir) {
		return syscall.EPERM
	}
	if flags&renameExchange != 0 {
		// The counterpart entry changes names too; hold it to the same bar.
		var dst syscall.Stat_t
		if err := fstatat(newParent.fd, newName, &dst, atSymlinkNofollow); err != nil {
			return errnoOf(err)
		}
		dstIsDir := dst.Mode&syscall.S_IFMT == syscall.S_IFDIR
		if f.maskedLocked(newParent, newName, dstIsDir) || f.maskedLocked(parent, name, dstIsDir) {
			return syscall.EPERM
		}
		// The counterpart also moves; a directory carrying a hidden entry
		// would relocate it just as the source could.
		if errno := f.refuseIfSubtreeMasked(newParent, newName, dstIsDir); errno != 0 {
			return errno
		}
	}
	// Moving a directory whose subtree currently hides a masked entry could
	// relocate that entry onto a visible path (anchored patterns are path-
	// relative). Refuse it, mirroring view mode where the masked path is a
	// live mountpoint and the parent rename fails EBUSY.
	if errno := f.refuseIfSubtreeMasked(parent, name, isDir); errno != 0 {
		return errno
	}

	var err error
	if flags == 0 {
		err = syscall.Renameat(parent.fd, name, newParent.fd, newName)
	} else {
		err = renameat2(parent.fd, name, newParent.fd, newName, flags)
	}
	if err != nil {
		return errnoOf(err)
	}

	// Keep cached locations current so rel() reflects the move.
	f.mu.Lock()
	for _, n := range f.nodes {
		if n.parent == parent && n.name == name {
			n.parent, n.name = newParent, newName
		} else if flags&renameExchange != 0 && n.parent == newParent && n.name == newName {
			n.parent, n.name = parent, name
		}
	}
	f.mu.Unlock()
	return 0
}

// refuseIfSubtreeMasked returns EBUSY when name under parent is a directory
// whose subtree currently hides a masked entry, so a rename that relocates it
// is refused. It is a no-op unless the pattern set is anchored (checkDirRename)
// — unanchored patterns match by basename and survive an ancestor rename.
func (f *FS) refuseIfSubtreeMasked(parent *node, name string, isDir bool) syscall.Errno {
	if !isDir || !f.checkDirRename {
		return 0
	}
	f.mu.Lock()
	relBase := f.relChild(parent, name)
	f.mu.Unlock()
	masked, err := f.subtreeHasMasked(parent.fd, name, relBase)
	if err != nil {
		return errnoOf(err)
	}
	if masked {
		return syscall.EBUSY
	}
	return 0
}

// subtreeHasMasked reports whether any entry in the subtree rooted at name
// (under the open parentFd, workspace-relative path relBase) is masked,
// short-circuiting on the first match. The walk is fd-relative with
// O_NOFOLLOW, so tree symlinks cannot redirect it outside the box tree; the
// filter is evaluated on the same compiled pattern set as every other lookup.
func (f *FS) subtreeHasMasked(parentFd int, name, relBase string) (bool, error) {
	dfd, err := syscall.Openat(parentFd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		// Turned into a non-directory/symlink or vanished under us: nothing
		// walkable to expose, and the rename below fails on its own if needed.
		if err == syscall.ENOTDIR || err == syscall.ELOOP || err == syscall.ENOENT {
			return false, nil
		}
		return false, err
	}
	defer syscall.Close(dfd)

	var subdirs []string
	buf := make([]byte, 32*1024)
	for {
		nread, err := syscall.ReadDirent(dfd, buf)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return false, err
		}
		if nread == 0 {
			break
		}
		b := buf[:nread]
		for len(b) >= 19 {
			reclen := int(binary.NativeEndian.Uint16(b[16:18]))
			if reclen < 19 || reclen > len(b) {
				return false, syscall.EIO
			}
			typ := uint32(b[18])
			nameBytes := b[19:reclen]
			if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
				nameBytes = nameBytes[:i]
			}
			child := string(nameBytes)
			b = b[reclen:]
			if child == "." || child == ".." {
				continue
			}
			isDir := typ == dtDir
			if typ == dtUnknown {
				var st syscall.Stat_t
				if err := fstatat(dfd, child, &st, atSymlinkNofollow); err == nil {
					isDir = st.Mode&syscall.S_IFMT == syscall.S_IFDIR
				}
			}
			if f.filter(relBase+"/"+child, isDir) {
				return true, nil
			}
			if isDir {
				subdirs = append(subdirs, child)
			}
		}
	}
	// Recurse only into unmasked subdirectories; depth is bounded by the tree.
	for _, child := range subdirs {
		masked, err := f.subtreeHasMasked(dfd, child, relBase+"/"+child)
		if err != nil {
			return false, err
		}
		if masked {
			return true, nil
		}
	}
	return false, nil
}

func (f *FS) Open(nodeid uint64, flags uint32) (openOut, syscall.Errno) {
	n, errno := f.getNode(nodeid)
	if errno != 0 {
		return openOut{}, errno
	}
	// The inode is already pinned; reopen it through /proc with the
	// requested access mode. Creation-family bits never apply here.
	oflags := int(flags) &^ (syscall.O_CREAT | syscall.O_EXCL | syscall.O_NOCTTY)
	fd, err := syscall.Open(procPath(n.fd), oflags, 0)
	if err != nil {
		return openOut{}, errnoOf(err)
	}
	return openOut{Fh: f.newHandle(fd, n, nil)}, 0
}

func (f *FS) Create(parentID uint64, name string, in *createIn) (entryOut, openOut, syscall.Errno) {
	parent, errno := f.getNode(parentID)
	if errno != 0 {
		return entryOut{}, openOut{}, errno
	}
	if !validName(name) {
		return entryOut{}, openOut{}, syscall.EINVAL
	}
	if f.maskedLocked(parent, name, false) {
		return entryOut{}, openOut{}, syscall.EPERM
	}
	oflags := int(in.Flags) | syscall.O_CREAT | syscall.O_NOFOLLOW
	fd, err := syscall.Openat(parent.fd, name, oflags, in.Mode&07777)
	if err != nil {
		return entryOut{}, openOut{}, errnoOf(err)
	}
	n, attr, errno := f.pin(parent, name)
	if errno != 0 {
		syscall.Close(fd)
		return entryOut{}, openOut{}, errno
	}
	return entryFor(n, attr), openOut{Fh: f.newHandle(fd, n, nil)}, 0
}

func (f *FS) Read(fh, offset uint64, size uint32, dst []byte) (int, syscall.Errno) {
	h, errno := f.getHandle(fh)
	if errno != 0 {
		return 0, errno
	}
	if uint32(len(dst)) > size {
		dst = dst[:size]
	}
	total := 0
	for total < len(dst) {
		nr, err := syscall.Pread(h.fd, dst[total:], int64(offset)+int64(total))
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, errnoOf(err)
		}
		if nr == 0 {
			break
		}
		total += nr
	}
	return total, 0
}

func (f *FS) Write(fh, offset uint64, data []byte) (uint32, syscall.Errno) {
	h, errno := f.getHandle(fh)
	if errno != 0 {
		return 0, errno
	}
	total := 0
	for total < len(data) {
		nw, err := syscall.Pwrite(h.fd, data[total:], int64(offset)+int64(total))
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, errnoOf(err)
		}
		total += nw
	}
	return uint32(total), 0
}

func (f *FS) Release(fh uint64) {
	f.mu.Lock()
	h, ok := f.handles[fh]
	delete(f.handles, fh)
	f.mu.Unlock()
	if ok {
		syscall.Close(h.fd)
	}
}

func (f *FS) Fsync(fh uint64, datasync bool) syscall.Errno {
	h, errno := f.getHandle(fh)
	if errno != 0 {
		return errno
	}
	if datasync {
		return errnoOf(syscall.Fdatasync(h.fd))
	}
	return errnoOf(syscall.Fsync(h.fd))
}

// Opendir snapshots the directory with the filter applied. The snapshot is
// per-open: a directory held open across host-side changes serves a
// consistent listing; reopening re-evaluates.
func (f *FS) Opendir(nodeid uint64) (openOut, syscall.Errno) {
	n, errno := f.getNode(nodeid)
	if errno != 0 {
		return openOut{}, errno
	}
	fd, err := syscall.Open(procPath(n.fd), syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return openOut{}, errnoOf(err)
	}
	ents, err := f.snapshotDir(n, fd)
	if err != nil {
		syscall.Close(fd)
		return openOut{}, errnoOf(err)
	}
	return openOut{Fh: f.newHandle(fd, n, ents)}, 0
}

// snapshotDir reads the real directory and drops masked names. DT_UNKNOWN
// entries are stat'ed so directory-only patterns apply correctly.
func (f *FS) snapshotDir(n *node, fd int) ([]dirEntry, error) {
	var selfSt syscall.Stat_t
	if err := fstatat(fd, "", &selfSt, atEmptyPath); err != nil {
		return nil, err
	}
	parentIno := selfSt.Ino
	if n.parent != nil {
		var pst syscall.Stat_t
		if err := fstatat(n.parent.fd, "", &pst, atEmptyPath); err == nil {
			parentIno = pst.Ino
		}
	}
	ents := []dirEntry{
		{name: ".", ino: selfSt.Ino, typ: dtDir},
		{name: "..", ino: parentIno, typ: dtDir},
	}

	buf := make([]byte, 32*1024)
	for {
		nread, err := syscall.ReadDirent(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if nread == 0 {
			break
		}
		b := buf[:nread]
		for len(b) >= 19 {
			ino := binary.NativeEndian.Uint64(b[0:8])
			reclen := int(binary.NativeEndian.Uint16(b[16:18]))
			if reclen < 19 || reclen > len(b) {
				return nil, syscall.EIO
			}
			typ := uint32(b[18])
			nameBytes := b[19:reclen]
			if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
				nameBytes = nameBytes[:i]
			}
			name := string(nameBytes)
			b = b[reclen:]
			if name == "." || name == ".." {
				continue
			}
			isDir := typ == dtDir
			if typ == dtUnknown {
				var st syscall.Stat_t
				if err := fstatat(fd, name, &st, atSymlinkNofollow); err == nil {
					if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
						isDir, typ = true, dtDir
					}
				}
			}
			if f.maskedLocked(n, name, isDir) {
				continue
			}
			ents = append(ents, dirEntry{name: name, ino: ino, typ: typ})
		}
	}
	return ents, nil
}

// Readdir serves the snapshot. Off in each record is the index of the
// next entry — the offset the kernel resumes with.
func (f *FS) Readdir(fh, offset uint64, size uint32, buf []byte) (int, syscall.Errno) {
	h, errno := f.getHandle(fh)
	if errno != 0 {
		return 0, errno
	}
	if h.ents == nil {
		return 0, syscall.ENOTDIR
	}
	out := 0
	for i := offset; i < uint64(len(h.ents)); i++ {
		e := h.ents[i]
		rec := direntAlign(direntSize + len(e.name))
		if out+rec > int(size) || out+rec > len(buf) {
			break
		}
		binary.NativeEndian.PutUint64(buf[out:], e.ino)
		binary.NativeEndian.PutUint64(buf[out+8:], i+1)
		binary.NativeEndian.PutUint32(buf[out+16:], uint32(len(e.name)))
		binary.NativeEndian.PutUint32(buf[out+20:], e.typ)
		copy(buf[out+24:], e.name)
		for p := out + 24 + len(e.name); p < out+rec; p++ {
			buf[p] = 0
		}
		out += rec
	}
	return out, 0
}

func (f *FS) Statfs(nodeid uint64) (kstatfs, syscall.Errno) {
	n, errno := f.getNode(nodeid)
	if errno != 0 {
		return kstatfs{}, errno
	}
	var st syscall.Statfs_t
	if err := syscall.Fstatfs(n.fd, &st); err != nil {
		return kstatfs{}, errnoOf(err)
	}
	return kstatfs{
		Blocks:  st.Blocks,
		Bfree:   st.Bfree,
		Bavail:  st.Bavail,
		Files:   st.Files,
		Ffree:   st.Ffree,
		Bsize:   uint32(st.Bsize),
		Namelen: uint32(st.Namelen),
		Frsize:  uint32(st.Frsize),
	}, 0
}

func (f *FS) Access(nodeid uint64, mask uint32) syscall.Errno {
	n, errno := f.getNode(nodeid)
	if errno != 0 {
		return errno
	}
	return errnoOf(syscall.Access(procPath(n.fd), mask))
}

func (f *FS) Fallocate(fh uint64, in *fallocateIn) syscall.Errno {
	h, errno := f.getHandle(fh)
	if errno != 0 {
		return errno
	}
	return errnoOf(syscall.Fallocate(h.fd, in.Mode, int64(in.Offset), int64(in.Length)))
}

func (f *FS) Lseek(fh uint64, in *lseekIn) (lseekOut, syscall.Errno) {
	h, errno := f.getHandle(fh)
	if errno != 0 {
		return lseekOut{}, errno
	}
	off, err := syscall.Seek(h.fd, int64(in.Offset), int(in.Whence))
	if err != nil {
		return lseekOut{}, errnoOf(err)
	}
	return lseekOut{Offset: uint64(off)}, 0
}

// unlinkat with flags; the syscall package's Unlinkat lacks the flags
// argument AT_REMOVEDIR needs.
func unlinkat(dirfd int, path string, flags int) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(flags))
	if e != 0 {
		return e
	}
	return nil
}

func renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint32) error {
	op, err := syscall.BytePtrFromString(oldpath)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(newpath)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(sysRenameat2,
		uintptr(olddirfd), uintptr(unsafe.Pointer(op)),
		uintptr(newdirfd), uintptr(unsafe.Pointer(np)), uintptr(flags), 0)
	if e != 0 {
		return e
	}
	return nil
}

// utimensatFd is utimensat(fd, NULL, ts, 0): operate on the fd itself.
func utimensatFd(fd int, ts *[2]syscall.Timespec) error {
	_, _, e := syscall.Syscall6(syscall.SYS_UTIMENSAT,
		uintptr(fd), 0, uintptr(unsafe.Pointer(ts)), 0, 0, 0)
	if e != 0 {
		return e
	}
	return nil
}
