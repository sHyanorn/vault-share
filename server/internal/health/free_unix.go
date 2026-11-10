//go:build unix

package health

import "syscall"

// freeBytes is the space an unprivileged process can still use on the
// filesystem that holds dir.
func freeBytes(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil // #nosec G115 -- a block size is positive
}
