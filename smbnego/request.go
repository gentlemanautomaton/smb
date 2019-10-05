package smbnego

import (
	"encoding/binary"

	"github.com/gentlemanautomaton/smb/smbcap"
	"github.com/gentlemanautomaton/smb/smbdialect"
	"github.com/gentlemanautomaton/smb/smbid"
	"github.com/gentlemanautomaton/smb/smbsecmode"
)

// Request interprets a slice of bytes as an SMB negotiate request packet.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5
type Request []byte

// Valid returns true if the request is valid.
func (r Request) Valid() bool {
	if len(r) < 36 {
		return false
	}

	// The spec requires the size field to be 65.
	if r.Size() != 36 {
		return false
	}

	// There must be at least one dialect requested
	if r.DialectCount() == 0 {
		return false
	}

	// The security mode must be an expected value
	switch r.SecurityMode() {
	case smbsecmode.SigningEnabled, smbsecmode.SigningRequired:
	default:
		return false
	}

	// The dialects must not overflow
	if 36+int(r.DialectCount())*2 > len(r) {
		return false
	}

	// In SMB 3.1.1 the negotiate context must not overflow
	if r.Dialects().Contains(smbdialect.SMB311) {
		start := int(r.NegotiateContextOffset())
		end := start + int(r.NegotiateContextCount())*8 // The size is variable but at least 8 bytes
		if end > len(r) {
			return false
		}
	}

	return true
}

// Size returns the structure size of the request. The specification
// requires that this be 36, regardless of the number of dialects or
// negotiation contexts.
func (r Request) Size() uint16 {
	return binary.LittleEndian.Uint16(r[0:2])
}

// SetSize sets the structure size of the request.
func (r Request) SetSize(size uint16) {
	binary.LittleEndian.PutUint16(r[0:2], size)
}

// DialectCount returns the dialect count of the request.
func (r Request) DialectCount() uint16 {
	return binary.LittleEndian.Uint16(r[2:4])
}

// SetDialectCount sets the dialect count of the request.
func (r Request) SetDialectCount(count uint16) {
	binary.LittleEndian.PutUint16(r[2:4], count)
}

// SecurityMode returns the security mode of the request.
func (r Request) SecurityMode() smbsecmode.Flags {
	return smbsecmode.Flags(binary.LittleEndian.Uint16(r[4:6]))
}

// SetSecurityMode sets the security mode of the request.
func (r Request) SetSecurityMode(flags smbsecmode.Flags) {
	binary.LittleEndian.PutUint16(r[4:6], uint16(flags))
}

// Capabilities returns the capability flags of the request.
func (r Request) Capabilities() smbcap.Flags {
	return smbcap.Flags(binary.LittleEndian.Uint32(r[8:12]))
}

// SetCapabilities sets the capability flags of the request.
func (r Request) SetCapabilities(flags smbcap.Flags) {
	binary.LittleEndian.PutUint32(r[8:12], uint32(flags))
}

// ClientID returns the client identifier of the request.
func (r Request) ClientID() (id smbid.ID) {
	id.Read(r[12:28])
	return
}

// SetClientID sets the client identifier of the request.
func (r Request) SetClientID(id smbid.ID) {
	id.Write(r[12:28])
}

// NegotiateContextOffset returns the offset of the first negotiate context
// within the request.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) NegotiateContextOffset() uint32 {
	return binary.LittleEndian.Uint32(r[28:32])
}

// SetNegotiateContextOffset sets the offset of the first negotiate context
// within the request.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) SetNegotiateContextOffset(size uint32) {
	binary.LittleEndian.PutUint32(r[28:32], size)
}

// NegotiateContextCount returns the context count of the request.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) NegotiateContextCount() uint16 {
	return binary.LittleEndian.Uint16(r[32:34])
}

// SetNegotiateContextCount sets the context count of the request.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) SetNegotiateContextCount(size uint16) {
	binary.LittleEndian.PutUint16(r[32:34], size)
}

// Dialects returns the dialect list from the request.
func (r Request) Dialects() smbdialect.List {
	const start = uint(36)
	end := start + uint(r.DialectCount())*2
	return smbdialect.List(r[start:end:end])
}

// NegotiateContext returns the bytes of the negotiate context list from the
// request.
//
// TODO: Return the context list as a strongly typed slice.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) NegotiateContext() []byte {
	return r[r.NegotiateContextOffset():]
}
