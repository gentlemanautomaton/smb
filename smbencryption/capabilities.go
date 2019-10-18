package smbencryption

import (
	"github.com/gentlemanautomaton/smb/smbtype"
)

// Capabilities interprets a slice of bytes as a set of encryption
// capabilities during SMB 3.1.1 protocol negotiation.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/16693be7-2b27-4d3b-804b-f605bde5bcdd
type Capabilities []byte

// CipherCount returns the number of supported encryption ciphers.
func (c Capabilities) CipherCount() uint16 {
	return smbtype.Uint16(c[0:2])
}

// SetCipherCount sets the number of supported encryption ciphers.
func (c Capabilities) SetCipherCount(count uint16) {
	smbtype.PutUint16(c[0:2], count)
}

// Ciphers returns the list of supported encryption ciphers.
func (c Capabilities) Ciphers() List {
	start := uint(2)
	length := uint(c.CipherCount()) * 2
	end := start + length
	return List(c[start:end:end])
}
