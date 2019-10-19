package smbserver

import (
	"github.com/gentlemanautomaton/smb"
	"github.com/gentlemanautomaton/smb/smbpacket"
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

// Marshal marshals a response and sends it to the client.
func (c *Conn) Marshal(messageID uint64, credits uint16, r Response) error {
	msg := c.Create(smbpacket.HeaderSize + r.Size())
	defer msg.Close()

	packet := smbpacket.Response(msg.Bytes())

	hdr := packet.Header()
	hdr.SetProtocol(smbpacket.SMB2)
	hdr.SetSize(smbpacket.HeaderSize)
	hdr.SetCommand(r.Command())
	hdr.SetCreditResponse(credits)
	hdr.SetFlags(smbpacket.ServerToClient)
	hdr.SetMessageID(messageID)

	r.Marshal(packet.Data())

	return c.Send(msg)
}
