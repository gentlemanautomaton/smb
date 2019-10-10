package smbintegrity

import "strconv"

// Algorithm identifies a type of cryptographic hashing algorithm used for
// preauthentication integrity during SMB 3.1.1 protocol negotiation.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5
type Algorithm uint16

// Possible preauthentication hash algorithms.
const (
	SHA512 = 0x0001
)

// String returns a string representation of the hash algorithm.
func (a Algorithm) String() string {
	switch a {
	case SHA512:
		return "SHA-512"
	default:
		return "Hash-" + strconv.Itoa(int(a))
	}
}
