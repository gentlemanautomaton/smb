package smbserver

import (
	"github.com/gentlemanautomaton/smb"
)

// Conn represents the server's view of an SMB connection. It holds
// connection-specific state.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0055d1e1-18fa-4c1c-8941-df7203d440c7
type Conn struct {
	smb.Conn
	Sequencer
	ConnState
	GlobalState
}
