package smbserver

import "github.com/gentlemanautomaton/smb"

// A Handler handles SMB connections.
type Handler interface {
	ServeSMB(smb.Conn)
}

// HandlerFunc is a function that can act as a Handler.
type HandlerFunc func(c smb.Conn)

// ServeSMB handles the given SMB connection.
func (h HandlerFunc) ServeSMB(c smb.Conn) {
	h(c)
}
