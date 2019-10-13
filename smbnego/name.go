package smbnego

import "github.com/gentlemanautomaton/smb/smbtype"

// Name interprets a slice of bytes as an SMB server name encoded as utf16.
type Name []byte

// String returns a string representation of the name.
func (n Name) String() string {
	return smbtype.String([]byte(n))
}
