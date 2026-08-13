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

// One box per workspace root means one lock per box, and with it the whole
// lock-ordering problem goes away: there is no second level to acquire out of
// order, so no deadlock to design against.
//
//	create/remove/recreate/start/stop a box -> exclusive box lock
//	run against a running box               -> shared box lock
//
// Locks are flock(2)-based: a lock dies with its holder, so a killed
// process cannot leave a stale lock — acquisition succeeds and the pid file
// content is simply outdated. Timeouts name the recorded holder pid rather
// than hanging.

type Lock struct {
	f    *os.File
	path string
}

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

// LockBoxExclusive guards a box's lifecycle: creation, removal, recreation,
// start and stop.
func (s *Store) LockBoxExclusive(key string) (*Lock, error) {
	return acquire(filepath.Join(s.BoxDir(key), "lock"), true, lockTimeout)
}

// LockBoxShared is the run lock: several commands may run inside one box at
// once, but none may run while it is being created or torn down.
func (s *Store) LockBoxShared(key string) (*Lock, error) {
	return acquire(filepath.Join(s.BoxDir(key), "lock"), false, lockTimeout)
}
