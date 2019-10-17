package smbpacket

import "strings"

// Flags declares a set of processing flags for an SMB packet.
type Flags uint32

// SMB packet processing flags.
const (
	// ServerToClient indicates that the packet is a response from the server.
	ServerToClient = 0x00000001 // SMB2_FLAGS_SERVER_TO_REDIR

	// Async indicates that the packet is in asynchronous form.
	Async = 0x00000002 // SMB2_FLAGS_ASYNC_COMMAND

	// Related indicates that the packet is a related operation that belongs
	// to a compounded request or response chain.
	Related = 0x00000004 // SMB2_FLAGS_RELATED_OPERATIONS

	// Signed indicates that the packet has been signed.
	Signed = 0x00000008 // SMB2_FLAGS_SIGNED

	// PriorityMask is a mask for the I/O priority bits of the packet.
	//
	// This flag is only valid in the SMB 3.1.1 dialect.
	PriorityMask = 0x00000070 // SMB2_FLAGS_PRIORITY_MASK

	// DFS indicates that the packet is part of a DFS operation.
	DFS = 0x10000000 // SMB2_FLAGS_DFS_OPERATIONS

	// Replay indicates that the packet is being replayed after a
	// transport failure.
	Replay = 0x20000000 // SMB2_FLAGS_REPLAY_OPERATION
)

// Match reports whether f contains all of the packet flags specified by c.
func (f Flags) Match(c Flags) bool {
	return f&c == c
}

// String returns a string representation of the packet flags.
func (f Flags) String() string {
	return f.Format("|", FlagNames)
}

// Format returns a string representation of the packet flags using the
// given separator and format.
func (f Flags) Format(sep string, format FlagFormat) string {
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

// FlagFormat describes a set of names for SMB packet flags.
type FlagFormat map[Flags]string

// FlagProtoNames maps individual flags to their names as defined by the SMB
// protocol specification.
var FlagProtoNames = FlagFormat{
	ServerToClient: "SMB2_FLAGS_SERVER_TO_REDIR",
	Async:          "SMB2_FLAGS_ASYNC_COMMAND",
	Related:        "SMB2_FLAGS_RELATED_OPERATIONS",
	Signed:         "SMB2_FLAGS_SIGNED",
	PriorityMask:   "SMB2_FLAGS_PRIORITY_MASK",
	DFS:            "SMB2_FLAGS_DFS_OPERATIONS",
	Replay:         "SMB2_FLAGS_REPLAY_OPERATION",
}

// FlagNames maps individual flags to their Go-style names.
var FlagNames = FlagFormat{
	ServerToClient: "ServerToClient",
	Async:          "Async",
	Related:        "Related",
	Signed:         "Signed",
	PriorityMask:   "PriorityMask",
	DFS:            "DFS",
	Replay:         "Replay",
}
