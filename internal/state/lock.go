package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Two-level locking:
//
//	create/remove a box, set the default box  -> exclusive project lock
//	recreate/start/stop a box                 -> exclusive box lock
//	run/attach against a running box          -> shared box lock
//
// Box locks are acquired after the project lock and released in reverse
// order; the API makes the other order unrepresentable by requiring a
// *ProjectLock to take a box lock while the project lock is held.
//
// Locks are flock(2)-based: a lock dies with its holder, so a killed
// process cannot leave a stale lock — acquisition succeeds and the pid file
// content is simply outdated. Timeouts name the recorded holder pid rather
// than hanging.

type Lock struct {
	f    *os.File
	path string
}

type ProjectLock struct{ Lock }

const lockTimeout = 10 * time.Second

func acquire(path string, exclusive bool, timeout time.Duration) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	deadline := time.Now().Add(timeout)
	for {
		err = syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			holder := "unknown pid"
			if b, rerr := os.ReadFile(path); rerr == nil && len(b) > 0 {
				holder = "pid " + strings.TrimSpace(string(b))
			}
			f.Close()
			return nil, fmt.Errorf("timed out after %s waiting for lock %s (held by %s)", timeout, path, holder)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if exclusive {
		_ = f.Truncate(0)
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	}
	return &Lock{f: f, path: path}, nil
}

func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}

// LockProject takes the exclusive project-level lock guarding box creation
// and removal, name allocation, default-box selection, and max_boxes
// enforcement.
func (s *Store) LockProject(key string) (*ProjectLock, error) {
	l, err := acquire(filepath.Join(s.ProjectDir(key), "lock"), true, lockTimeout)
	if err != nil {
		return nil, err
	}
	return &ProjectLock{*l}, nil
}

// LockBoxExclusive guards one box's lifecycle (recreate, start, stop). The
// project lock must be held, enforcing acquisition order.
func (s *Store) LockBoxExclusive(pl *ProjectLock, key, instance string) (*Lock, error) {
	if pl == nil {
		return nil, fmt.Errorf("internal error: box lock requested without the project lock (ordering violation)")
	}
	return acquire(filepath.Join(s.BoxDir(key, instance), "lock"), true, lockTimeout)
}

// LockBoxShared is the run/attach lock. Concurrent runs against different
// boxes never contend beyond a brief project-lock read, so the shared lock
// is taken directly on the box.
func (s *Store) LockBoxShared(key, instance string) (*Lock, error) {
	return acquire(filepath.Join(s.BoxDir(key, instance), "lock"), false, lockTimeout)
}
