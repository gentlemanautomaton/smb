package smbsecmode

import "strconv"

// Flags identify SMB security mode flags during protocol negotiation.
type Flags uint16

// SMB security mode flags.
const (
	SigningEnabled  = 0x0001 // SMB2_NEGOTIATE_SIGNING_ENABLED
	SigningRequired = 0x0002 // SMB2_NEGOTIATE_SIGNING_REQUIRED
)

// Flags returns a string representation of the security mode flags.
func (f Flags) String() string {
	switch f {
	case SigningRequired:
		return "SigningRequired"
	case SigningEnabled:
		return "SigningEnabled"
	default:
		return "SecMode " + strconv.Itoa(int(f))
	}
}
