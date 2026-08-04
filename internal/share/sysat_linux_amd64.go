package share

import "syscall"

const (
	sysFstatat   = syscall.SYS_NEWFSTATAT
	sysRenameat2 = 316 // not in the syscall package on this arch
)
