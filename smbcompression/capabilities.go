package smbcompression

import (
	"encoding/binary"
)

// Capabilities interprets a slice of bytes as a set of compression
// capabilities during SMB 3.1.1 protocol negotiation.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271
type Capabilities []byte

// AlgorithmCount returns the number of supported compression algorithms.
func (c Capabilities) AlgorithmCount() uint16 {
	return binary.LittleEndian.Uint16(c[0:2])
}

// SetAlgorithmCount sets the number of supported compression algorithms.
func (c Capabilities) SetAlgorithmCount(count uint16) {
	binary.LittleEndian.PutUint16(c[0:2], count)
}

// Algorithms returns the list of supported compression algorithms.
func (c Capabilities) Algorithms() List {
	start := uint(8)
	length := uint(c.AlgorithmCount()) * 2
	end := start + length
	return List(c[start:end:end])
}
