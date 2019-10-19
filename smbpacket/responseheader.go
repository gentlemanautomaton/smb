package smbpacket

import (
	"github.com/gentlemanautomaton/smb/smbcommand"
	"github.com/gentlemanautomaton/smb/smbtype"
)

// ResponseHeader interprets a slice of bytes as an SMB response packet
// header.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79
type ResponseHeader []byte

// Valid returns true if the header is valid.
func (h ResponseHeader) Valid() bool {
	if len(h) < HeaderSize {
		return false
	}
	if h.Protocol() != SMB2 {
		return false
	}

	return true
}

// Protocol returns the protocol ID of the packet.
func (h ResponseHeader) Protocol() Protocol {
	return Protocol{h[0], h[1], h[2], h[3]}
}

// SetProtocol sets the protocol ID of the packet.
func (h ResponseHeader) SetProtocol(p Protocol) {
	h[0], h[1], h[2], h[3] = p[0], p[1], p[2], p[3]
}

// Size returns the structure size of the header.
func (h ResponseHeader) Size() uint16 {
	return smbtype.Uint16(h[4:6])
}

// SetSize sets the structure size of the header.
func (h ResponseHeader) SetSize(size uint16) {
	smbtype.PutUint16(h[4:6], size)
}

// CreditCharge returns the credit charge of the response. This represents
// the cost of the packet.
//
// This field is not valid in the SMB 2.0.2 dialect. It is valid in all other
// dialects.
func (h ResponseHeader) CreditCharge() uint16 {
	return smbtype.Uint16(h[6:8])
}

// SetCreditCharge sets the credit charge of the response. This represents
// the cost of the packet.
//
// This field is not valid in the SMB 2.0.2 dialect. It is valid in all other
// dialects.
func (h ResponseHeader) SetCreditCharge(charge uint16) {
	smbtype.PutUint16(h[6:8], charge)
}

// Status returns the status from the response. It indicates the success or
// failure of the command.
func (h ResponseHeader) Status() uint32 {
	return smbtype.Uint32(h[8:12])
}

// SetStatus sets the status of the response. It indicates the success or
// failure of the command.
func (h ResponseHeader) SetStatus(status uint32) {
	smbtype.PutUint32(h[8:12], status)
}

// Command returns the command code of the response.
func (h ResponseHeader) Command() smbcommand.Code {
	return smbcommand.Code(smbtype.Uint16(h[12:14]))
}

// SetCommand sets the command code of the response.
func (h ResponseHeader) SetCommand(command smbcommand.Code) {
	smbtype.PutUint16(h[12:14], uint16(command))
}

// CreditResponse returns the number of credits granted in the response.
func (h ResponseHeader) CreditResponse() uint16 {
	return smbtype.Uint16(h[14:16])
}

// SetCreditResponse sets the number of credits granted in the response.
func (h ResponseHeader) SetCreditResponse(credits uint16) {
	smbtype.PutUint16(h[14:16], credits)
}

// Flags returns the processing flags for the response.
func (h ResponseHeader) Flags() Flags {
	return Flags(smbtype.Uint32(h[16:20]))
}

// SetFlags sets the processing flags for the response.
func (h ResponseHeader) SetFlags(f Flags) {
	smbtype.PutUint32(h[16:20], uint32(f))
}

// NextCommand returns the byte offset of the next response in the message, if
// there is one. It returns zero if there are no more responses. The offset is
// relative to the start of h.
func (h ResponseHeader) NextCommand() uint32 {
	return smbtype.Uint32(h[20:24])
}

// SetNextCommand sets the byte offset of the next response in the message.
func (h ResponseHeader) SetNextCommand(offset uint32) {
	smbtype.PutUint32(h[20:24], offset)
}

// MessageID returns the message ID of the response.
func (h ResponseHeader) MessageID() uint64 {
	return smbtype.Uint64(h[24:32])
}

// SetMessageID sets the message ID of the response.
func (h ResponseHeader) SetMessageID(message uint64) {
	smbtype.PutUint64(h[24:32], message)
}

// TreeID returns the tree ID of the response.
//
// This field is only valid for synchronous responses.
func (h ResponseHeader) TreeID() uint32 {
	return smbtype.Uint32(h[36:40])
}

// SetTreeID sets the tree ID of the response.
//
// This field is only valid for synchronous responses.
func (h ResponseHeader) SetTreeID(tree uint32) {
	smbtype.PutUint32(h[36:40], tree)
}

// AsyncID returns the asynchronous ID of the response.
//
// This field is only valid for asynchronous responses.
func (h ResponseHeader) AsyncID() uint64 {
	return smbtype.Uint64(h[32:40])
}

// SetAsyncID sets the asynchronous ID of the response.
//
// This field is only valid for asynchronous responses.
func (h ResponseHeader) SetAsyncID(async uint64) {
	smbtype.PutUint64(h[32:40], async)
}

// SessionID returns the session ID of the response.
func (h ResponseHeader) SessionID() uint64 {
	return smbtype.Uint64(h[40:48])
}

// SetSessionID sets the session ID of the response.
func (h ResponseHeader) SetSessionID(tree uint32) {
	smbtype.PutUint32(h[40:48], tree)
}

// Signature returns the cryptographic signature of the response.
func (h ResponseHeader) Signature() Signature {
	return Signature{
		h[48], h[49], h[50], h[51], h[52], h[53], h[54], h[55],
		h[56], h[57], h[58], h[59], h[60], h[61], h[62], h[63],
	}
}

// SetSignature sets the cryptographic signature of the response.
func (h ResponseHeader) SetSignature(s Signature) {
	s.Marshal(h[48:64])
}
