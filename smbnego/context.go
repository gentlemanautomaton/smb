package smbnego

import (
	"encoding/binary"

	"github.com/gentlemanautomaton/smb/smbcompression"
	"github.com/gentlemanautomaton/smb/smbencryption"
	"github.com/gentlemanautomaton/smb/smbintegrity"
)

// ContextHeaderLength is the number of bytes required for a valid negotiation
// context header.
const ContextHeaderLength = 8

// Context interprets a slice of bytes as an SMB negotiation context during
// SMB 3.1.1 protocol negotiation.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7
type Context []byte

// Type returns the type of the context.
func (c Context) Type() ContextType {
	return ContextType(binary.LittleEndian.Uint16(c[0:2]))
}

// Length returns the length of the context data in bytes.
func (c Context) Length() uint16 {
	return binary.LittleEndian.Uint16(c[2:4])
}

// Data returns the context's data as a slice of bytes.
func (c Context) Data() []byte {
	return c[8 : 8+c.Length()]
}

// PreauthIntegrityCaps interprets the context's data as a set of
// preauthentication integrity capabilities.
func (c Context) PreauthIntegrityCaps() smbintegrity.Capabilities {
	return smbintegrity.Capabilities(c.Data())
}

// EncryptionCaps interprets the context's data as a set of encryption
// capabilities.
func (c Context) EncryptionCaps() smbencryption.Capabilities {
	return smbencryption.Capabilities(c.Data())
}

// CompressionCaps interprets the context's data as a set of compression
// capabilities.
func (c Context) CompressionCaps() smbcompression.Capabilities {
	return smbcompression.Capabilities(c.Data())
}

// NetName interprets the context's data as the name of the server the client
// wishes to connect to.
func (c Context) NetName() Name {
	return Name(c.Data())
}
