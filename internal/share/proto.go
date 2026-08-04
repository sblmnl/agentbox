// Package share is agentbox's own share daemon: a filtering passthrough
// filesystem mounted host-side at a box's view root, so the runtime's
// virtiofsd serves a view agentbox controls. It is what delivers Layer 3
// (`mask_mode = "filter"`): masked paths are reported ENOENT at lookup and
// omitted from directory listings, evaluated live against the same compiled
// pattern set as Layer 0 — from the same code (internal/ignore); agentbox
// never maintains two mask generators.
//
// The daemon is the same agentbox binary running the hidden `fsd`
// subcommand, one process per box, mirroring the netpol proxyd pattern.
// This file is the FUSE kernel wire protocol: fixed-layout, native-endian
// structs exchanged over /dev/fuse. Only what the passthrough needs is
// defined; unknown opcodes are answered ENOSYS.
package share

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Protocol version negotiated in INIT. 7.31 predates the flags2/extension
// handling introduced in 7.36, keeping the INIT exchange fixed-layout; the
// kernel uses min(kernel, ours).
const (
	protoMajor = 7
	protoMinor = 31
)

// maxWrite is the largest WRITE payload advertised in INIT. Reads from
// /dev/fuse must use a buffer at least this large plus headers.
const maxWrite = 1 << 20

// bufSize is the request read buffer: max_write plus room for headers.
const bufSize = maxWrite + 4096

// FUSE opcodes (linux/fuse.h).
const (
	opLookup      = 1
	opForget      = 2
	opGetattr     = 3
	opSetattr     = 4
	opReadlink    = 5
	opSymlink     = 6
	opMknod       = 8
	opMkdir       = 9
	opUnlink      = 10
	opRmdir       = 11
	opRename      = 12
	opLink        = 13
	opOpen        = 14
	opRead        = 15
	opWrite       = 16
	opStatfs      = 17
	opRelease     = 18
	opFsync       = 20
	opSetxattr    = 21
	opGetxattr    = 22
	opListxattr   = 23
	opRemovexattr = 24
	opFlush       = 25
	opInit        = 26
	opOpendir     = 27
	opReaddir     = 28
	opReleasedir  = 29
	opFsyncdir    = 30
	opGetlk       = 31
	opSetlk       = 32
	opSetlkw      = 33
	opAccess      = 34
	opCreate      = 35
	opInterrupt   = 36
	opDestroy     = 38
	opFallocate   = 43
	opReaddirplus = 44
	opRename2     = 45
	opLseek       = 46
	opBatchForget = 42
)

// INIT flags (the subset advertised).
const (
	initBigWrites      = 1 << 5
	initParallelDirops = 1 << 18
	initMaxPages       = 1 << 22
)

// SETATTR valid bits.
const (
	fattrMode     = 1 << 0
	fattrUID      = 1 << 1
	fattrGID      = 1 << 2
	fattrSize     = 1 << 3
	fattrAtime    = 1 << 4
	fattrMtime    = 1 << 5
	fattrFh       = 1 << 6
	fattrAtimeNow = 1 << 7
	fattrMtimeNow = 1 << 8
	fattrCtime    = 1 << 10
)

// rootNodeID is the kernel's fixed id for the mount root.
const rootNodeID = 1

const (
	inHeaderSize  = 40
	outHeaderSize = 16
)

// inHeader precedes every kernel request.
type inHeader struct {
	Len         uint32
	Opcode      uint32
	Unique      uint64
	Nodeid      uint64
	UID         uint32
	GID         uint32
	PID         uint32
	TotalExtlen uint16
	Padding     uint16
}

// outHeader precedes every reply. Error is a negated errno or 0.
type outHeader struct {
	Len    uint32
	Error  int32
	Unique uint64
}

// fuseAttr is the wire form of a stat result. Flags is padding below 7.32;
// zero either way.
type fuseAttr struct {
	Ino       uint64
	Size      uint64
	Blocks    uint64
	Atime     uint64
	Mtime     uint64
	Ctime     uint64
	AtimeNsec uint32
	MtimeNsec uint32
	CtimeNsec uint32
	Mode      uint32
	Nlink     uint32
	UID       uint32
	GID       uint32
	Rdev      uint32
	Blksize   uint32
	Flags     uint32
}

// entryOut answers LOOKUP, and the entry half of CREATE.
type entryOut struct {
	Nodeid         uint64
	Generation     uint64
	EntryValid     uint64
	AttrValid      uint64
	EntryValidNsec uint32
	AttrValidNsec  uint32
	Attr           fuseAttr
}

type getattrIn struct {
	GetattrFlags uint32
	Dummy        uint32
	Fh           uint64
}

type attrOut struct {
	AttrValid     uint64
	AttrValidNsec uint32
	Dummy         uint32
	Attr          fuseAttr
}

type setattrIn struct {
	Valid     uint32
	Padding   uint32
	Fh        uint64
	Size      uint64
	LockOwner uint64
	Atime     uint64
	Mtime     uint64
	Ctime     uint64
	AtimeNsec uint32
	MtimeNsec uint32
	CtimeNsec uint32
	Mode      uint32
	Unused4   uint32
	UID       uint32
	GID       uint32
	Unused5   uint32
}

type mknodIn struct {
	Mode    uint32
	Rdev    uint32
	Umask   uint32
	Padding uint32
}

type mkdirIn struct {
	Mode  uint32
	Umask uint32
}

type renameIn struct {
	Newdir uint64
}

type rename2In struct {
	Newdir  uint64
	Flags   uint32
	Padding uint32
}

type linkIn struct {
	Oldnodeid uint64
}

type openIn struct {
	Flags     uint32
	OpenFlags uint32
}

type openOut struct {
	Fh        uint64
	OpenFlags uint32
	Padding   uint32
}

type createIn struct {
	Flags     uint32
	Mode      uint32
	Umask     uint32
	OpenFlags uint32
}

type readIn struct {
	Fh        uint64
	Offset    uint64
	Size      uint32
	ReadFlags uint32
	LockOwner uint64
	Flags     uint32
	Padding   uint32
}

type writeIn struct {
	Fh         uint64
	Offset     uint64
	Size       uint32
	WriteFlags uint32
	LockOwner  uint64
	Flags      uint32
	Padding    uint32
}

type writeOut struct {
	Size    uint32
	Padding uint32
}

type releaseIn struct {
	Fh           uint64
	Flags        uint32
	ReleaseFlags uint32
	LockOwner    uint64
}

type flushIn struct {
	Fh        uint64
	Unused    uint32
	Padding   uint32
	LockOwner uint64
}

type fsyncIn struct {
	Fh         uint64
	FsyncFlags uint32
	Padding    uint32
}

type accessIn struct {
	Mask    uint32
	Padding uint32
}

type forgetIn struct {
	Nlookup uint64
}

type batchForgetIn struct {
	Count uint32
	Dummy uint32
}

type forgetOne struct {
	Nodeid  uint64
	Nlookup uint64
}

type fallocateIn struct {
	Fh      uint64
	Offset  uint64
	Length  uint64
	Mode    uint32
	Padding uint32
}

type lseekIn struct {
	Fh      uint64
	Offset  uint64
	Whence  uint32
	Padding uint32
}

type lseekOut struct {
	Offset uint64
}

type kstatfs struct {
	Blocks  uint64
	Bfree   uint64
	Bavail  uint64
	Files   uint64
	Ffree   uint64
	Bsize   uint32
	Namelen uint32
	Frsize  uint32
	Padding uint32
	Spare   [6]uint32
}

type initIn struct {
	Major        uint32
	Minor        uint32
	MaxReadahead uint32
	Flags        uint32
}

type initOut struct {
	Major               uint32
	Minor               uint32
	MaxReadahead        uint32
	Flags               uint32
	MaxBackground       uint16
	CongestionThreshold uint16
	MaxWrite            uint32
	TimeGran            uint32
	MaxPages            uint16
	MapAlignment        uint16
	Flags2              uint32
	Unused              [7]uint32
}

// dirent is the wire form of one READDIR entry; the name follows,
// padded to 8 bytes.
type dirent struct {
	Ino     uint64
	Off     uint64
	Namelen uint32
	Type    uint32
}

const direntSize = 24

// direntAlign pads a dirent record length to the protocol's 8-byte grid.
func direntAlign(n int) int { return (n + 7) &^ 7 }

// decode reads a fixed-layout struct from b. FUSE structs are
// native-endian by definition.
func decode(b []byte, v any) error {
	return binary.Read(bytes.NewReader(b), binary.NativeEndian, v)
}

// encode appends the fixed layout of v to buf.
func encode(buf *bytes.Buffer, v any) {
	// Writing fixed-size structs to a bytes.Buffer cannot fail.
	if err := binary.Write(buf, binary.NativeEndian, v); err != nil {
		panic(fmt.Sprintf("share: encoding %T: %v", v, err))
	}
}

// parseName extracts a NUL-terminated name from a request body.
func parseName(b []byte) (string, []byte, error) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, fmt.Errorf("unterminated name in request body")
	}
	return string(b[:i]), b[i+1:], nil
}
