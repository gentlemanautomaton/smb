package smbmultiproto

// requestHeader interprets a slice of bytes as an SMB multi-protocol request
// packet header compatible with SMB version 1.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f
type requestHeader []byte

// Valid returns true if the header is valid.
func (h requestHeader) Valid() bool {
	if len(h) < 32 {
		return false
	}
	if h[0] != 0xFF || h[1] != 'S' || h[2] != 'M' || h[3] != 'B' {
		return false
	}
	return true
}

// IsNegotiate returns true if the request is a negotiate command.
func (h requestHeader) IsNegotiate() bool {
	return h[4] == commandNegotiate
}
