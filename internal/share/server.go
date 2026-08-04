//go:build linux

package share

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

// Conn serves the FUSE protocol for one FS over one device fd. The fd is
// /dev/fuse in production; tests drive the same loop over a socketpair,
// which is what lets the filter semantics be exercised without a mount.
type Conn struct {
	dev *os.File
	fs  *FS

	wmu  sync.Mutex // replies are single writes; serialize them
	bufs sync.Pool

	// negotiated INIT state
	minor uint32
}

func NewConn(dev *os.File, fs *FS) *Conn {
	c := &Conn{dev: dev, fs: fs}
	c.bufs.New = func() any {
		b := make([]byte, bufSize)
		return &b
	}
	return c
}

// Serve reads requests until the device reports the mount is gone
// (ENODEV after unmount) or the fd closes. Each request is dispatched on
// its own goroutine; replies are serialized.
func (c *Conn) Serve() error {
	for {
		bufp := c.bufs.Get().(*[]byte)
		buf := *bufp
		n, err := c.dev.Read(buf)
		if err != nil {
			c.bufs.Put(bufp)
			if errnoFromIO(err) == syscall.ENODEV || err == io.EOF || errnoFromIO(err) == syscall.EBADF {
				return nil // unmounted: clean shutdown
			}
			if errnoFromIO(err) == syscall.EINTR || errnoFromIO(err) == syscall.EAGAIN {
				continue
			}
			return err
		}
		if n < inHeaderSize {
			c.bufs.Put(bufp)
			continue
		}
		var hdr inHeader
		if err := decode(buf[:inHeaderSize], &hdr); err != nil {
			c.bufs.Put(bufp)
			continue
		}
		body := buf[inHeaderSize:n]

		switch hdr.Opcode {
		case opInit:
			// INIT must complete before anything else; handle inline.
			c.handleInit(&hdr, body)
			c.bufs.Put(bufp)
		case opForget, opBatchForget, opInterrupt, opDestroy:
			// No reply is defined for these.
			c.handleNoReply(&hdr, body)
			c.bufs.Put(bufp)
		default:
			go func() {
				defer c.bufs.Put(bufp)
				c.dispatch(&hdr, body)
			}()
		}
	}
}

func errnoFromIO(err error) syscall.Errno {
	for err != nil {
		if e, ok := err.(syscall.Errno); ok {
			return e
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return 0
}

// reply writes one full response in a single write, as /dev/fuse requires.
func (c *Conn) reply(unique uint64, errno syscall.Errno, payload []byte) {
	var out bytes.Buffer
	encode(&out, &outHeader{
		Len:    uint32(outHeaderSize + len(payload)),
		Error:  -int32(errno),
		Unique: unique,
	})
	out.Write(payload)
	c.wmu.Lock()
	_, _ = c.dev.Write(out.Bytes())
	c.wmu.Unlock()
}

func (c *Conn) replyStruct(unique uint64, vs ...any) {
	var body bytes.Buffer
	for _, v := range vs {
		encode(&body, v)
	}
	c.reply(unique, 0, body.Bytes())
}

func (c *Conn) handleInit(hdr *inHeader, body []byte) {
	var in initIn
	if err := decode(body[:min(len(body), 16)], &in); err != nil || in.Major != protoMajor {
		c.reply(hdr.Unique, syscall.EPROTO, nil)
		return
	}
	c.minor = min(in.Minor, protoMinor)
	out := initOut{
		Major:               protoMajor,
		Minor:               c.minor,
		MaxReadahead:        maxWrite,
		Flags:               in.Flags & (initBigWrites | initParallelDirops | initMaxPages),
		MaxBackground:       16,
		CongestionThreshold: 12,
		MaxWrite:            maxWrite,
		TimeGran:            1,
		MaxPages:            maxWrite / 4096,
	}
	c.replyStruct(hdr.Unique, &out)
}

func (c *Conn) handleNoReply(hdr *inHeader, body []byte) {
	switch hdr.Opcode {
	case opForget:
		var in forgetIn
		if decode(body, &in) == nil {
			c.fs.Forget(hdr.Nodeid, in.Nlookup)
		}
	case opBatchForget:
		var in batchForgetIn
		if len(body) < 8 || decode(body[:8], &in) != nil {
			return
		}
		rest := body[8:]
		for i := uint32(0); i < in.Count && len(rest) >= 16; i++ {
			var one forgetOne
			if decode(rest[:16], &one) == nil {
				c.fs.Forget(one.Nodeid, one.Nlookup)
			}
			rest = rest[16:]
		}
	}
	// opInterrupt, opDestroy: nothing to do — no operation here blocks
	// indefinitely, and teardown is driven by unmount.
}

// dispatch decodes one request, runs it against the FS, and replies.
func (c *Conn) dispatch(hdr *inHeader, body []byte) {
	defer func() {
		if r := recover(); r != nil {
			// A malformed request must not take the daemon (and with it
			// every mask) down; answer EIO and keep serving.
			fmt.Fprintf(os.Stderr, "fsd: panic serving opcode %d: %v\n", hdr.Opcode, r)
			c.reply(hdr.Unique, syscall.EIO, nil)
		}
	}()

	switch hdr.Opcode {
	case opLookup:
		name, _, err := parseName(body)
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		out, errno := c.fs.Lookup(hdr.Nodeid, name)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opGetattr:
		out, errno := c.fs.Getattr(hdr.Nodeid)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opSetattr:
		var in setattrIn
		if decode(body, &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		out, errno := c.fs.Setattr(hdr.Nodeid, &in)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opReadlink:
		target, errno := c.fs.Readlink(hdr.Nodeid)
		if errno != 0 {
			c.reply(hdr.Unique, errno, nil)
			return
		}
		c.reply(hdr.Unique, 0, target)

	case opMknod:
		var in mknodIn
		if len(body) < 16 || decode(body[:16], &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		name, _, err := parseName(body[16:])
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		out, errno := c.fs.Mknod(hdr.Nodeid, name, &in)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opMkdir:
		var in mkdirIn
		if len(body) < 8 || decode(body[:8], &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		name, _, err := parseName(body[8:])
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		out, errno := c.fs.Mkdir(hdr.Nodeid, name, &in)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opUnlink:
		name, _, err := parseName(body)
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		c.reply(hdr.Unique, c.fs.Unlink(hdr.Nodeid, name), nil)

	case opRmdir:
		name, _, err := parseName(body)
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		c.reply(hdr.Unique, c.fs.Rmdir(hdr.Nodeid, name), nil)

	case opSymlink:
		name, rest, err := parseName(body)
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		target, _, err := parseName(rest)
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		out, errno := c.fs.Symlink(hdr.Nodeid, name, target)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opRename, opRename2:
		var newdir uint64
		var flags uint32
		var rest []byte
		if hdr.Opcode == opRename {
			var in renameIn
			if len(body) < 8 || decode(body[:8], &in) != nil {
				c.reply(hdr.Unique, syscall.EINVAL, nil)
				return
			}
			newdir, rest = in.Newdir, body[8:]
		} else {
			var in rename2In
			if len(body) < 16 || decode(body[:16], &in) != nil {
				c.reply(hdr.Unique, syscall.EINVAL, nil)
				return
			}
			newdir, flags, rest = in.Newdir, in.Flags, body[16:]
		}
		oldName, rest, err := parseName(rest)
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		newName, _, err := parseName(rest)
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		c.reply(hdr.Unique, c.fs.Rename(hdr.Nodeid, oldName, newdir, newName, flags), nil)

	case opLink:
		var in linkIn
		if len(body) < 8 || decode(body[:8], &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		name, _, err := parseName(body[8:])
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		out, errno := c.fs.Link(in.Oldnodeid, hdr.Nodeid, name)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opOpen:
		var in openIn
		if decode(body, &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		out, errno := c.fs.Open(hdr.Nodeid, in.Flags)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opCreate:
		var in createIn
		if len(body) < 16 || decode(body[:16], &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		name, _, err := parseName(body[16:])
		if err != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		entry, open, errno := c.fs.Create(hdr.Nodeid, name, &in)
		if errno != 0 {
			c.reply(hdr.Unique, errno, nil)
			return
		}
		c.replyStruct(hdr.Unique, &entry, &open)

	case opRead:
		var in readIn
		if decode(body, &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		if in.Size > maxWrite {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		dst := make([]byte, in.Size)
		n, errno := c.fs.Read(in.Fh, in.Offset, in.Size, dst)
		if errno != 0 {
			c.reply(hdr.Unique, errno, nil)
			return
		}
		c.reply(hdr.Unique, 0, dst[:n])

	case opWrite:
		var in writeIn
		if len(body) < 40 || decode(body[:40], &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		data := body[40:]
		if uint32(len(data)) < in.Size {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		n, errno := c.fs.Write(in.Fh, in.Offset, data[:in.Size])
		if errno != 0 {
			c.reply(hdr.Unique, errno, nil)
			return
		}
		c.replyStruct(hdr.Unique, &writeOut{Size: n})

	case opRelease, opReleasedir:
		var in releaseIn
		if decode(body, &in) == nil {
			c.fs.Release(in.Fh)
		}
		c.reply(hdr.Unique, 0, nil)

	case opFlush:
		c.reply(hdr.Unique, 0, nil)

	case opFsync, opFsyncdir:
		var in fsyncIn
		if decode(body, &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		c.reply(hdr.Unique, c.fs.Fsync(in.Fh, in.FsyncFlags&1 != 0), nil)

	case opOpendir:
		out, errno := c.fs.Opendir(hdr.Nodeid)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opReaddir:
		var in readIn
		if decode(body, &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		if in.Size > maxWrite {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		buf := make([]byte, in.Size)
		n, errno := c.fs.Readdir(in.Fh, in.Offset, in.Size, buf)
		if errno != 0 {
			c.reply(hdr.Unique, errno, nil)
			return
		}
		c.reply(hdr.Unique, 0, buf[:n])

	case opStatfs:
		out, errno := c.fs.Statfs(hdr.Nodeid)
		c.replyOrErr(hdr.Unique, errno, &out)

	case opAccess:
		var in accessIn
		if decode(body, &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		c.reply(hdr.Unique, c.fs.Access(hdr.Nodeid, in.Mask), nil)

	case opFallocate:
		var in fallocateIn
		if decode(body, &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		c.reply(hdr.Unique, c.fs.Fallocate(in.Fh, &in), nil)

	case opLseek:
		var in lseekIn
		if decode(body, &in) != nil {
			c.reply(hdr.Unique, syscall.EINVAL, nil)
			return
		}
		out, errno := c.fs.Lseek(in.Fh, &in)
		c.replyOrErr(hdr.Unique, errno, &out)

	default:
		// Locks, xattrs, ioctls, readdirplus (not negotiated): declaring
		// ENOSYS makes the kernel handle locally or stop asking.
		c.reply(hdr.Unique, syscall.ENOSYS, nil)
	}
}

func (c *Conn) replyOrErr(unique uint64, errno syscall.Errno, v any) {
	if errno != 0 {
		c.reply(unique, errno, nil)
		return
	}
	c.replyStruct(unique, v)
}
