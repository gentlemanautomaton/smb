package smbnego

import "strconv"

// ContextType identifies a type of negotiation context during SMB 3.1.1
// protocol negotiation.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7
type ContextType uint16

// SMB negotiation context types.
const (
	PreauthIntegrityCaps = 0x0001 // SMB2_PREAUTH_INTEGRITY_CAPABILITIES
	EncryptionCaps       = 0x0002 // SMB2_ENCRYPTION_CAPABILITIES
	CompressionCaps      = 0x0003 // SMB2_COMPRESSION_CAPABILITIES
	NetnameID            = 0x0004 // SMB2_NETNAME_NEGOTIATE_CONTEXT_ID
)

// String returns a string representation of the context type.
func (t ContextType) String() string {
	switch t {
	case PreauthIntegrityCaps:
		return "PreauthIntegrityCaps"
	case EncryptionCaps:
		return "EncryptionCaps"
	case CompressionCaps:
		return "CompressionCaps"
	case NetnameID:
		return "NetnameID"
	default:
		return "ContextType-" + strconv.Itoa(int(t))
	}
}
