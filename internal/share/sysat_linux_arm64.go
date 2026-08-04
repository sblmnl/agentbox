package share

import "syscall"

const (
	sysFstatat   = syscall.SYS_FSTATAT
	sysRenameat2 = 276 // not in the syscall package on this arch
)
