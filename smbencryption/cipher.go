package smbencryption

import "strconv"

// Cipher identifies a cryptographic cipher used for encryption.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/16693be7-2b27-4d3b-804b-f605bde5bcdd
type Cipher uint16

// Possible encryption ciphers.
const (
	AES128CCM = 0x0001
	AES128GCM = 0x0002
)

// String returns a string representation of the encryption cipher.
func (c Cipher) String() string {
	switch c {
	case AES128CCM:
		return "AES-128-CCM"
	case AES128GCM:
		return "AES-128-GCM"
	default:
		return "Cipher-" + strconv.Itoa(int(c))
	}
}
