package smbcap

import "strings"

// Flags declares which optional SMB2 features are supported during
// protocol negotiation.
type Flags uint32

const (
	// DFS indicates support for Distributed File System
	DFS = 0x00000001 // SMB2_GLOBAL_CAP_DFS

	// Leasing indicates support for leasing.
	Leasing = 0x00000002 // SMB2_GLOBAL_CAP_LEASING

	// LargeMTU indicates support for multi-credit operations.
	LargeMTU = 0x00000004 // SMB2_GLOBAL_CAP_LARGE_MTU

	// MultiChannel indicates support for a single session having multiple
	// channels.
	MultiChannel = 0x00000008 // SMB2_GLOBAL_CAP_MULTI_CHANNEL

	// PersistentHandles indicates support for persistent handles.
	PersistentHandles = 0x00000010 // SMB2_GLOBAL_CAP_PERSISTENT_HANDLES

	// DirectoryLeasing indicates support for directory leasing.
	DirectoryLeasing = 0x00000020 // SMB2_GLOBAL_CAP_DIRECTORY_LEASING

	// Encryption indicates support for encrypted packets.
	Encryption = 0x00000040 // SMB2_GLOBAL_CAP_ENCRYPTION
)

// Match reports whether f contains all of the capabilities specified by c.
func (f Flags) Match(c Flags) bool {
	return f&c == c
}

// String returns a string representation of the capability flags.
func (f Flags) String() string {
	return f.Format("|", GoNames)
}

// Format returns a string representation of the capability flags using the
// given separator and format.
func (f Flags) Format(sep string, format Format) string {
	if s, ok := format[f]; ok {
		return s
	}

	var matched []string
	for i := 0; i < 32; i++ {
		flag := Flags(1 << uint32(i))
		if f.Match(flag) {
			if s, ok := format[flag]; ok {
				matched = append(matched, s)
			}
		}
	}

	return strings.Join(matched, sep)
}
