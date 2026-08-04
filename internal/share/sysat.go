//go:build linux

package share

// Raw *at syscall wrappers the stdlib syscall package does not provide.
// These are the only path the daemon takes into the tree: every call is a
// single component relative to a pinned dirfd (or an empty path meaning
// the pinned fd itself), never a multi-component resolution.

import (
	"syscall"
	"unsafe"
)

func fstatat(dirfd int, path string, st *syscall.Stat_t, flags int) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(sysFstatat,
		uintptr(dirfd), uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(st)), uintptr(flags), 0, 0)
	if e != 0 {
		return e
	}
	return nil
}

func readlinkat(dirfd int, path string, buf []byte) (int, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	var b unsafe.Pointer
	if len(buf) > 0 {
		b = unsafe.Pointer(&buf[0])
	}
	n, _, e := syscall.Syscall6(syscall.SYS_READLINKAT,
		uintptr(dirfd), uintptr(unsafe.Pointer(p)),
		uintptr(b), uintptr(len(buf)), 0, 0)
	if e != 0 {
		return 0, e
	}
	return int(n), nil
}

func symlinkat(target string, newdirfd int, linkpath string) error {
	t, err := syscall.BytePtrFromString(target)
	if err != nil {
		return err
	}
	l, err := syscall.BytePtrFromString(linkpath)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall(syscall.SYS_SYMLINKAT,
		uintptr(unsafe.Pointer(t)), uintptr(newdirfd), uintptr(unsafe.Pointer(l)))
	if e != 0 {
		return e
	}
	return nil
}

func linkat(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) error {
	op, err := syscall.BytePtrFromString(oldpath)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(newpath)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(syscall.SYS_LINKAT,
		uintptr(olddirfd), uintptr(unsafe.Pointer(op)),
		uintptr(newdirfd), uintptr(unsafe.Pointer(np)), uintptr(flags), 0)
	if e != 0 {
		return e
	}
	return nil
}
