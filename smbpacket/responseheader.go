package smbpacket

import (
	"encoding/binary"

	"github.com/gentlemanautomaton/smb/smbcommand"
)

// ResponseHeader interprets a slice of bytes as an SMB response packet
// header.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79
type ResponseHeader []byte

// Valid returns true if the header is valid.
func (h ResponseHeader) Valid() bool {
	if len(h) < 64 {
		return false
	}
	if h[0] != 0xFE || h[1] != 'S' || h[2] != 'M' || h[3] != 'B' {
		return false
	}

	return true
}

// Protocol returns the protocol ID of the packet.
func (h ResponseHeader) Protocol() uint32 {
	return binary.LittleEndian.Uint32(h[0:4])
}

// Size returns the structure size of the header.
func (h ResponseHeader) Size() uint16 {
	return binary.LittleEndian.Uint16(h[4:6])
}

// CreditCharge returns the credit charge of the response. This represents
// the cost of the packet.
//
// This field is not valid in the SMB 2.0.2 dialect. It is valid in all other
// dialects.
func (h ResponseHeader) CreditCharge() uint16 {
	return binary.LittleEndian.Uint16(h[6:8])
}

// Status returns the status from the response. It indicates the success or
// failure of the command.
func (h ResponseHeader) Status() uint32 {
	return binary.LittleEndian.Uint32(h[8:12])
}

// Command returns the command code of the response.
func (h ResponseHeader) Command() smbcommand.Code {
	return smbcommand.Code(binary.LittleEndian.Uint16(h[12:14]))
}

// CreditResponse returns the number credits granted in the response.
func (h ResponseHeader) CreditResponse() uint16 {
	return binary.LittleEndian.Uint16(h[14:16])
}

// Flags returns the processing flags for the response.
func (h ResponseHeader) Flags() uint16 {
	return binary.LittleEndian.Uint16(h[16:20])
}

// NextCommand returns the byte offset of the next response in the message, if
// there is one. Returns zero if there are no more responses. The offset is
// relative to the start of h.
func (h ResponseHeader) NextCommand() uint32 {
	return binary.LittleEndian.Uint32(h[20:24])
}

// MessageID returns the message ID of the response.
func (h ResponseHeader) MessageID() uint64 {
	return binary.LittleEndian.Uint64(h[24:32])
}

// TreeID returns the tree ID of the response.
//
// This field is only valid for synchronous responses.
func (h ResponseHeader) TreeID() uint32 {
	return binary.LittleEndian.Uint32(h[36:40])
}

// AsyncID returns the asynchronous ID of the response.
//
// This field is only valid for asynchronous responses.
func (h ResponseHeader) AsyncID() uint64 {
	return binary.LittleEndian.Uint64(h[32:40])
}

// SessionID returns the session ID of the response.
func (h ResponseHeader) SessionID() uint64 {
	return binary.LittleEndian.Uint64(h[40:48])
}

// Signature returns the cryptographic signature of the response.
func (h ResponseHeader) Signature() [16]byte {
	return [16]byte{
		h[48], h[49], h[50], h[51], h[52], h[53], h[54], h[55],
		h[56], h[57], h[58], h[59], h[60], h[61], h[62], h[63],
	}
}
