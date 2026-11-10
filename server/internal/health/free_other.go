//go:build !unix

package health

import "math"

// freeBytes is not measured on this platform; the check always passes.
func freeBytes(string) (uint64, error) {
	return math.MaxUint64, nil
}
