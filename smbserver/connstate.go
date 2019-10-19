package smbserver

import (
	"time"

	"github.com/gentlemanautomaton/smb/smbcap"
	"github.com/gentlemanautomaton/smb/smbdialect"
	"github.com/gentlemanautomaton/smb/smbsecmode"
)

// ConnState stores information about a connection on the server.
type ConnState struct {
	ClientCapabilities smbcap.Flags
	Dialect            smbdialect.State
	CreationTime       time.Time
	ClientSecurity     smbsecmode.Flags
	SupportMultiCredit bool
	MaxTransactSize    uint32
	MaxReadSize        uint32
	MaxWriteSize       uint32
	// RequestList
	// AsyncCommandList
	// SessionTable
	// PreauthSessionTable
}
