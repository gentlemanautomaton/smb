package smbintegrity

import (
	"encoding/binary"
)

// Capabilities interprets a slice of bytes as a set of preauthentication
// integrity capabilities during SMB 3.1.1 protocol negotiation.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5
type Capabilities []byte

// AlgorithmCount returns the number of supported preauthentication hash
// algorithms.
func (c Capabilities) AlgorithmCount() uint16 {
	return binary.LittleEndian.Uint16(c[0:2])
}

// SetAlgorithmCount sets the number of supported preauthentication hash
// algorithms.
func (c Capabilities) SetAlgorithmCount(count uint16) {
	binary.LittleEndian.PutUint16(c[0:2], count)
}

// SaltLength returns the length of the salt used for preauthentication
// integrity.
func (c Capabilities) SaltLength() uint16 {
	return binary.LittleEndian.Uint16(c[2:4])
}

// SetSaltLength sets the length of the salt used for preauthentication
// integrity.
func (c Capabilities) SetSaltLength(length uint16) {
	binary.LittleEndian.PutUint16(c[2:4], length)
}

// Algorithms returns the list of supported preauthentication hash algorithms.
func (c Capabilities) Algorithms() List {
	start := uint(4)
	length := uint(c.AlgorithmCount()) * 2
	end := start + length
	return List(c[start:end:end])
}

// Salt returns the salt used for preauthentication integrity.
func (c Capabilities) Salt() []byte {
	start := uint(4) + uint(c.AlgorithmCount())*2
	length := uint(c.SaltLength())
	end := start + length
	return []byte(c[start:end:end])
}
