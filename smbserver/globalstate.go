package smbserver

import "github.com/gentlemanautomaton/smb/smbid"

// GlobalState stores global information about the server.
type GlobalState struct {
	Server                smbid.ID
	RequireMessageSigning bool
	EncryptionSupported   bool
	CompressionSupported  bool
}
