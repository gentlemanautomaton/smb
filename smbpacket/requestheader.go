package smbpacket

import (
	"github.com/gentlemanautomaton/smb/smbcommand"
	"github.com/gentlemanautomaton/smb/smbtype"
)

// RequestHeader interprets a slice of bytes as an SMB request packet header.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79
type RequestHeader []byte

// Valid returns true if the header is valid.
func (h RequestHeader) Valid() bool {
	if len(h) < HeaderSize {
		return false
	}
	if h.Protocol() != SMB2 {
		return false
	}

	return true
}

// Protocol returns the protocol ID of the packet.
func (h RequestHeader) Protocol() Protocol {
	return Protocol{h[0], h[1], h[2], h[3]}
}

// SetProtocol sets the protocol ID of the packet.
func (h RequestHeader) SetProtocol(p Protocol) {
	h[0], h[1], h[2], h[3] = p[0], p[1], p[2], p[3]
}

// Size returns the structure size of the header.
func (h RequestHeader) Size() uint16 {
	return smbtype.Uint16(h[4:6])
}

// SetSize sets the structure size of the header.
func (h RequestHeader) SetSize(size uint16) {
	smbtype.PutUint16(h[4:6], size)
}

// CreditCharge returns the credit charge of the request. This represents
// the cost of the packet.
//
// This field is not valid in the SMB 2.0.2 dialect. It is valid in all other
// dialects.
func (h RequestHeader) CreditCharge() uint16 {
	return smbtype.Uint16(h[6:8])
}

// SetCreditCharge sets the credit charge of the request. This represents
// the cost of the packet.
//
// This field is not valid in the SMB 2.0.2 dialect. It is valid in all other
// dialects.
func (h RequestHeader) SetCreditCharge(charge uint16) {
	smbtype.PutUint16(h[6:8], charge)
}

// ChannelSequence returns the channel sequence of the request. It indicates
// a channel change to the server.
//
// This field is only valid in the SMB 3.x dialects.
func (h RequestHeader) ChannelSequence() uint16 {
	return smbtype.Uint16(h[8:10])
}

// SetChannelSequence sets the channel sequence of the request. It indicates
// a channel change to the server.
//
// This field is only valid in the SMB 3.x dialects.
func (h RequestHeader) SetChannelSequence(sequence uint16) {
	smbtype.PutUint16(h[8:10], sequence)
}

// Status returns the status from the request.
//
// This field is only valid in the SMB 2.0.2 and 2.1 dialects. It must be 0.
func (h RequestHeader) Status() uint32 {
	return smbtype.Uint32(h[8:12])
}

// Command returns the command code of the request.
func (h RequestHeader) Command() smbcommand.Code {
	return smbcommand.Code(smbtype.Uint16(h[12:14]))
}

// SetCommand sets the command code of the request.
func (h RequestHeader) SetCommand(command smbcommand.Code) {
	smbtype.PutUint16(h[12:14], uint16(command))
}

// CreditRequest returns the number of credits requested in the request.
func (h RequestHeader) CreditRequest() uint16 {
	return smbtype.Uint16(h[14:16])
}

// SetCreditRequest sets the number of credits requested in the request.
func (h RequestHeader) SetCreditRequest(credits uint16) {
	smbtype.PutUint16(h[14:16], credits)
}

// Flags returns the processing flags for the request.
func (h RequestHeader) Flags() Flags {
	return Flags(smbtype.Uint32(h[16:20]))
}

// SetFlags sets the processing flags for the request.
func (h RequestHeader) SetFlags(f Flags) {
	smbtype.PutUint32(h[16:20], uint32(f))
}

// NextCommand returns the byte offset of the next request in the message, if
// there is one. Returns zero if there are no more requests. The offset is
// relative to the start of h.
func (h RequestHeader) NextCommand() uint32 {
	return smbtype.Uint32(h[20:24])
}

// SetNextCommand sets the byte offset of the next request in the message.
func (h RequestHeader) SetNextCommand(offset uint32) {
	smbtype.PutUint32(h[20:24], offset)
}

// MessageID returns the message ID of the request.
func (h RequestHeader) MessageID() uint64 {
	return smbtype.Uint64(h[24:32])
}

// SetMessageID sets the message ID of the request.
func (h RequestHeader) SetMessageID(message uint64) {
	smbtype.PutUint64(h[24:32], message)
}

// TreeID returns the tree ID of the request.
//
// This field is only valid for synchronous requests.
func (h RequestHeader) TreeID() uint32 {
	return smbtype.Uint32(h[36:40])
}

// SetTreeID sets the tree ID of the request.
//
// This field is only valid for synchronous requests.
func (h RequestHeader) SetTreeID(tree uint32) {
	smbtype.PutUint32(h[36:40], tree)
}

// AsyncID returns the asynchronous ID of the request.
//
// This field is only valid for asynchronous requests.
func (h RequestHeader) AsyncID() uint64 {
	return smbtype.Uint64(h[32:40])
}

// SetAsyncID sets the asynchronous ID of the request.
//
// This field is only valid for asynchronous requests.
func (h RequestHeader) SetAsyncID(async uint64) {
	smbtype.PutUint64(h[32:40], async)
}

// SessionID returns the session ID of the request.
func (h RequestHeader) SessionID() uint64 {
	return smbtype.Uint64(h[40:48])
}

// SetSessionID sets the session ID of the request.
func (h RequestHeader) SetSessionID(tree uint32) {
	smbtype.PutUint32(h[40:48], tree)
}

// Signature returns the cryptographic signature of the request.
func (h RequestHeader) Signature() Signature {
	return Signature{
		h[48], h[49], h[50], h[51], h[52], h[53], h[54], h[55],
		h[56], h[57], h[58], h[59], h[60], h[61], h[62], h[63],
	}
}

// SetSignature sets the cryptographic signature of the request.
func (h RequestHeader) SetSignature(s Signature) {
	s.Marshal(h[48:64])
}
