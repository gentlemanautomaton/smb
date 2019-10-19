package smbnego

import (
	"strconv"
	"strings"

	"github.com/gentlemanautomaton/smb/smbcap"
	"github.com/gentlemanautomaton/smb/smbdialect"
	"github.com/gentlemanautomaton/smb/smbid"
	"github.com/gentlemanautomaton/smb/smbsecmode"
	"github.com/gentlemanautomaton/smb/smbtype"
)

// RequestSize is the number of bytes required for the fixed portion
// an SMB negotiation request.
const RequestSize = 36

// Request interprets a slice of bytes as an SMB negotiation request packet.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5
type Request []byte

// Valid returns true if the request is valid.
func (r Request) Valid() bool {
	if len(r) < RequestSize {
		return false
	}

	// The spec requires the size field to be 36
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
	if RequestSize+int(r.DialectCount())*2 > len(r) {
		return false
	}

	// In SMB 3.1.1 the negotiation contexts must not overflow
	if r.Dialects().Contains(smbdialect.SMB311) {
		// Make sure the context count is compatible with the size of the
		// request. The size of each context is variable but at least 8 bytes.
		minimumLength := uint(r.ContextOffset()) + uint(r.ContextCount())*ContextHeaderLength
		if minimumLength > uint(len(r)) {
			return false
		}

		// Rely on the context list implementation to determine its own validity
		if !r.ContextList().Valid(r.ContextCount()) {
			return false
		}
	}

	return true
}

// Size returns the structure size of the request. The specification
// requires that this be 36, regardless of the number of dialects or
// negotiation contexts.
func (r Request) Size() uint16 {
	return smbtype.Uint16(r[0:2])
}

// SetSize sets the structure size of the request.
func (r Request) SetSize(size uint16) {
	smbtype.PutUint16(r[0:2], size)
}

// DialectCount returns the dialect count of the request.
func (r Request) DialectCount() uint16 {
	return smbtype.Uint16(r[2:4])
}

// SetDialectCount sets the dialect count of the request.
func (r Request) SetDialectCount(count uint16) {
	smbtype.PutUint16(r[2:4], count)
}

// SecurityMode returns the security mode of the request.
func (r Request) SecurityMode() smbsecmode.Flags {
	return smbsecmode.Flags(smbtype.Uint16(r[4:6]))
}

// SetSecurityMode sets the security mode of the request.
func (r Request) SetSecurityMode(flags smbsecmode.Flags) {
	smbtype.PutUint16(r[4:6], uint16(flags))
}

// Capabilities returns the capability flags of the request.
func (r Request) Capabilities() smbcap.Flags {
	return smbcap.Flags(smbtype.Uint32(r[8:12]))
}

// SetCapabilities sets the capability flags of the request.
func (r Request) SetCapabilities(flags smbcap.Flags) {
	smbtype.PutUint32(r[8:12], uint32(flags))
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

// ContextOffset returns the offset of the first negotiation context in the
// request.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) ContextOffset() uint32 {
	return smbtype.Uint32(r[28:32])
}

// SetContextOffset sets the offset of the first negotiation context in the
// request.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) SetContextOffset(size uint32) {
	smbtype.PutUint32(r[28:32], size)
}

// ContextCount returns the negotiation context count of the request.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) ContextCount() uint16 {
	return smbtype.Uint16(r[32:34])
}

// SetContextCount sets the negotiation context count of the request.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) SetContextCount(count uint16) {
	smbtype.PutUint16(r[32:34], count)
}

// Dialects returns the dialect list from the request.
func (r Request) Dialects() smbdialect.List {
	const start = uint(RequestSize)
	end := start + uint(r.DialectCount())*2
	return smbdialect.List(r[start:end:end])
}

// ContextList returns the negotiation context list from the request.
//
// If r is valid the returned list is guaranteed to be valid.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Request) ContextList() ContextList {
	return ContextList(r[r.ContextOffset():])
}

// Summary returns a multi-line string representation of the request.
func (r Request) Summary() string {
	var lines []string
	lines = append(lines, "----Negotiate Request---")
	lines = append(lines, "  Size: "+strconv.Itoa(int(r.Size())))
	lines = append(lines, "  Dialect Count: "+strconv.Itoa(int(r.DialectCount())))
	lines = append(lines, "  Security Mode: "+r.SecurityMode().String())
	lines = append(lines, "  Capabilities: "+r.Capabilities().String())
	lines = append(lines, "  Client ID: "+r.ClientID().String())
	dialects := r.Dialects()
	for i := 0; i < dialects.Count(); i++ {
		lines = append(lines, "  Dialect: "+dialects.Member(i).String())
	}
	lines = append(lines, "-------")
	return strings.Join(lines, "\n")
}
