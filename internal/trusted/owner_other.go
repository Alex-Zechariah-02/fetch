// The owner check of a trusted file where ownership is not a Unix user ID:
// access is set by the system's own controls, which the operator owns.

//go:build !unix

package trusted

import "os"

func owner(os.FileInfo) error { return nil }
