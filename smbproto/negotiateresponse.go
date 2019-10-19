package smbproto

import (
	"fmt"
	"time"

	"github.com/gentlemanautomaton/smb/smbcap"
	"github.com/gentlemanautomaton/smb/smbcommand"
	"github.com/gentlemanautomaton/smb/smbdialect"
	"github.com/gentlemanautomaton/smb/smbid"
	"github.com/gentlemanautomaton/smb/smbnego"
	"github.com/gentlemanautomaton/smb/smbsecmode"
)

// NegotiateResponse holds SMB negotiation response data that can be
// serialized as an SMB packet.
type NegotiateResponse struct {
	Dialect         smbdialect.Revision
	SecMode         smbsecmode.Flags
	Server          smbid.ID
	Caps            smbcap.Flags
	MaxTransactSize uint32
	MaxReadSize     uint32
	MaxWriteSize    uint32
	SystemTime      time.Time
	SecurityBuffer  []byte
}

// Command returns the type of command of the response.
func (r NegotiateResponse) Command() smbcommand.Code {
	return smbcommand.Negotiate
}

// Status returns the status of the response.
func (r NegotiateResponse) Status() uint32 {
	return 0
}

// Size returns the number of bytes required to marshal the negotiation
// response. It excludes the packet header.
func (r NegotiateResponse) Size() int {
	s := smbnego.ResponseSize
	s += len(r.SecurityBuffer)
	// TODO: Include negotiation contexts
	return s
}

// Marshal marshals r as an SMB negotiation response to data.
func (r NegotiateResponse) Marshal(data []byte) {
	response := smbnego.Response(data)
	response.SetSize(65)
	response.SetSecurityMode(r.SecMode | smbsecmode.SigningEnabled)
	response.SetDialectRevision(r.Dialect)
	if r.Dialect == smbdialect.SMB311 {
		//response.SetContextCount(3)
	}
	response.SetServerID(r.Server)
	response.SetCapabilities(r.Caps)
	response.SetMaxTransactSize(r.MaxTransactSize)
	response.SetMaxReadSize(r.MaxReadSize)
	response.SetMaxWriteSize(r.MaxWriteSize)
	response.SetSystemTime(r.SystemTime)
	response.SetSecurityBuffer(r.SecurityBuffer)

	fmt.Println(response.Summary())
}
