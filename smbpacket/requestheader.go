package smbpacket

import (
	"encoding/binary"

	"github.com/gentlemanautomaton/smb/smbcommand"
)

// RequestHeader interprets a slice of bytes as an SMB request packet
// header.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79
type RequestHeader []byte

// Valid returns true if the header is valid.
func (h RequestHeader) Valid() bool {
	if len(h) < 64 {
		return false
	}
	if h[0] != 0xFE || h[1] != 'S' || h[2] != 'M' || h[3] != 'B' {
		return false
	}

	return true
}

// Protocol returns the protocol ID of the packet.
func (h RequestHeader) Protocol() uint32 {
	return binary.LittleEndian.Uint32(h[0:4])
}

// Size returns the structure size of the header.
func (h RequestHeader) Size() uint16 {
	return binary.LittleEndian.Uint16(h[4:6])
}

// CreditCharge returns the credit charge from h.
// Not valid in the SMB 2.0.2 dialect.
func (h RequestHeader) CreditCharge() uint16 {
	return binary.LittleEndian.Uint16(h[6:8])
}

// ChannelSequence returns the channel sequence of the request. It indicates
// a channel change to the server.
//
// This field is only valid in the SMB 3.x dialects.
func (h RequestHeader) ChannelSequence() uint16 {
	return binary.LittleEndian.Uint16(h[8:10])
}

// Status returns the status from the request.
//
// This field is only valid in the SMB 2.0.2 and 2.1 dialects.
func (h RequestHeader) Status() uint32 {
	return binary.LittleEndian.Uint32(h[8:12])
}

// Command returns the command code of the request.
func (h RequestHeader) Command() smbcommand.Code {
	return smbcommand.Code(binary.LittleEndian.Uint16(h[12:14]))
}

// CreditRequest returns the number credits requested in the request.
func (h RequestHeader) CreditRequest() uint16 {
	return binary.LittleEndian.Uint16(h[6:8])
}

// Flags returns the processing flags for the request.
func (h RequestHeader) Flags() uint16 {
	return binary.LittleEndian.Uint16(h[16:20])
}

// NextCommand returns the byte offset of the next request in the message, if
// there is one. Returns zero if there are no more requests. The offset is
// relative to the start of h.
func (h RequestHeader) NextCommand() uint32 {
	return binary.LittleEndian.Uint32(h[20:24])
}

// MessageID returns the message ID of the request.
func (h RequestHeader) MessageID() uint64 {
	return binary.LittleEndian.Uint64(h[24:32])
}

// TreeID returns the tree ID of the request.
//
// This field is only valid for synchronous requests.
func (h RequestHeader) TreeID() uint32 {
	return binary.LittleEndian.Uint32(h[36:40])
}

// AsyncID returns the asynchronous ID of the request.
//
// This field is only valid for asynchronous requests.
func (h RequestHeader) AsyncID() uint64 {
	return binary.LittleEndian.Uint64(h[32:40])
}

// SessionID returns the session ID of the request.
func (h RequestHeader) SessionID() uint64 {
	return binary.LittleEndian.Uint64(h[40:48])
}

// Signature returns the cryptographic signature of the request.
func (h RequestHeader) Signature() [16]byte {
	return [16]byte{
		h[48], h[49], h[50], h[51], h[52], h[53], h[54], h[55],
		h[56], h[57], h[58], h[59], h[60], h[61], h[62], h[63],
	}
}
