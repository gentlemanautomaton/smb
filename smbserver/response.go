package smbserver

import "github.com/gentlemanautomaton/smb/smbcommand"

// Response can be marshaled into a message.
type Response interface {
	Command() smbcommand.Code
	Status() uint32 // TODO: Make this strongly typed
	Size() int
	Marshal([]byte)
}
