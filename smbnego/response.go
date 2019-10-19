package smbnego

import (
	"strconv"
	"strings"
	"time"

	"github.com/gentlemanautomaton/smb/smbcap"
	"github.com/gentlemanautomaton/smb/smbdialect"
	"github.com/gentlemanautomaton/smb/smbid"
	"github.com/gentlemanautomaton/smb/smbsecmode"
	"github.com/gentlemanautomaton/smb/smbtype"
)

// ResponseSize is the number of bytes required for the fixed portion
// an SMB negotiation response.
const ResponseSize = 64

// Response interprets a slice of bytes as an SMB negotiation response packet.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5
type Response []byte

// Valid returns true if the response is valid.
func (r Response) Valid() bool {
	if len(r) < ResponseSize {
		return false
	}

	// The spec requires the size field to be 65
	if r.Size() != 65 {
		return false
	}

	// The security buffer must not overflow
	if int(r.SecurityBufferOffset())+int(r.SecurityBufferLength())-headerSize > len(r) {
		return false
	}

	// In SMB 3.1.1 the negotiation contexts must not overflow
	if r.DialectRevision() == smbdialect.SMB311 {
		// Make sure the context count is compatible with the size of the
		// response. The size of each context is variable but at least 8 bytes.
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

// Size returns the structure size of the response. The specification requires
// that this be 65, regardless of the size of the security buffer or the
// number of negotiation contexts.
func (r Response) Size() uint16 {
	return smbtype.Uint16(r[0:2])
}

// SetSize sets the structure size of the response.
func (r Response) SetSize(size uint16) {
	smbtype.PutUint16(r[0:2], size)
}

// SecurityMode returns the security mode of the response.
func (r Response) SecurityMode() smbsecmode.Flags {
	return smbsecmode.Flags(smbtype.Uint16(r[2:4]))
}

// SetSecurityMode sets the security mode of the response.
func (r Response) SetSecurityMode(flags smbsecmode.Flags) {
	smbtype.PutUint16(r[2:4], uint16(flags))
}

// DialectRevision returns the dialect revision of the response.
func (r Response) DialectRevision() smbdialect.Revision {
	return smbdialect.Revision(smbtype.Uint16(r[4:6]))
}

// SetDialectRevision sets the dialect revision of the response.
func (r Response) SetDialectRevision(revision smbdialect.Revision) {
	smbtype.PutUint16(r[4:6], uint16(revision))
}

// ContextCount returns the context count of the response.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Response) ContextCount() uint16 {
	return smbtype.Uint16(r[6:8])
}

// SetContextCount sets the context count of the response.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Response) SetContextCount(size uint16) {
	smbtype.PutUint16(r[6:8], size)
}

// ServerID returns the server identifier of the response.
func (r Response) ServerID() (id smbid.ID) {
	id.Read(r[8:24])
	return
}

// SetServerID sets the server identifier of the response.
func (r Response) SetServerID(id smbid.ID) {
	id.Write(r[8:24])
}

// Capabilities returns the capability flags of the response.
func (r Response) Capabilities() smbcap.Flags {
	return smbcap.Flags(smbtype.Uint32(r[24:28]))
}

// SetCapabilities sets the capability flags of the response.
func (r Response) SetCapabilities(flags smbcap.Flags) {
	smbtype.PutUint32(r[24:28], uint32(flags))
}

// MaxTransactSize returns the maximum transaction size of the response.
func (r Response) MaxTransactSize() uint32 {
	return smbtype.Uint32(r[28:32])
}

// SetMaxTransactSize sets the maximum transaction size of the response.
func (r Response) SetMaxTransactSize(size uint32) {
	smbtype.PutUint32(r[28:32], size)
}

// MaxReadSize returns the maximum read size of the response.
func (r Response) MaxReadSize() uint32 {
	return smbtype.Uint32(r[32:36])
}

// SetMaxReadSize sets the maximum read size of the response.
func (r Response) SetMaxReadSize(size uint32) {
	smbtype.PutUint32(r[32:36], size)
}

// MaxWriteSize returns the maximum write size of the response.
func (r Response) MaxWriteSize() uint32 {
	return smbtype.Uint32(r[36:40])
}

// SetMaxWriteSize sets the maximum write size of the response.
func (r Response) SetMaxWriteSize(size uint32) {
	smbtype.PutUint32(r[36:40], size)
}

// SystemTime returns the system time of the response.
func (r Response) SystemTime() time.Time {
	return smbtype.Time(r[40:48])
}

// SetSystemTime sets the system time of the response.
func (r Response) SetSystemTime(t time.Time) {
	smbtype.PutTime(r[40:48], t)
}

// ServerStartTime returns the server start time of the response.
func (r Response) ServerStartTime() time.Time {
	return smbtype.Time(r[48:56])
}

// SetServerStartTime sets the server start time of the response.
func (r Response) SetServerStartTime(t time.Time) {
	smbtype.PutTime(r[48:56], t)
}

// SecurityBufferOffset returns the offset of the security buffer in bytes
// from the start of the packet header.
func (r Response) SecurityBufferOffset() uint16 {
	return smbtype.Uint16(r[56:58])
}

// SetSecurityBufferOffset sets the offset of the security buffer in bytes
// from the start of the packet header.
func (r Response) SetSecurityBufferOffset(offset uint16) {
	smbtype.PutUint16(r[56:58], offset)
}

// SecurityBufferLength returns the length of the security buffer within the
// response.
func (r Response) SecurityBufferLength() uint16 {
	return smbtype.Uint16(r[58:60])
}

// SetSecurityBufferLength sets the length of the security buffer within the
// response.
func (r Response) SetSecurityBufferLength(length uint16) {
	smbtype.PutUint16(r[58:60], length)
}

// SecurityBuffer returns the bytes of the security buffer from the response.
func (r Response) SecurityBuffer() []byte {
	start := uint(r.SecurityBufferOffset()) - headerSize
	length := uint(r.SecurityBufferLength())
	end := start + length
	return r[start:end:end]
}

// SetSecurityBuffer sets the bytes of the security buffer within the
// response. It also updates the security buffer offset and length
// automatically.
//
// If len(v) exceeds MaxSecurityBuffer the call will panic.
//
// If the response is too small to hold all of v the call will panic.
func (r Response) SetSecurityBuffer(v []byte) {
	length := len(v)
	if length > MaxSecurityBuffer {
		panic("smbnego: response: security buffer exceeds maximum length")
	}
	if len(r)-ResponseSize < length {
		panic("smbnego: response: security buffer is too large to fit in response")
	}
	r.SetSecurityBufferOffset(headerSize + ResponseSize)
	r.SetSecurityBufferLength(uint16(length))
	copy(r[ResponseSize:], v)
}

// ContextOffset returns the offset of the first negotiate context
// in bytes from the start of the packet header.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Response) ContextOffset() uint32 {
	return smbtype.Uint32(r[60:64])
}

// SetContextOffset sets the offset of the first negotiate context
// in bytes from the start of the packet header.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Response) SetContextOffset(size uint32) {
	smbtype.PutUint32(r[60:64], size)
}

// ContextList returns the negotiation context list from the response.
//
// If r is valid the returned list is guaranteed to be valid.
//
// This field is only valid in the SMB 3.1.1 dialect.
func (r Response) ContextList() ContextList {
	start := uint(r.ContextOffset()) - headerSize
	return ContextList(r[start:])
}

// Summary returns a multi-line string representation of the response.
func (r Response) Summary() string {
	var lines []string
	lines = append(lines, "----Negotiate Response---")
	lines = append(lines, "  Size: "+strconv.Itoa(int(r.Size())))
	lines = append(lines, "  Security Mode: "+r.SecurityMode().String())
	lines = append(lines, "  Dialect Revision: "+r.DialectRevision().String())
	lines = append(lines, "  Server ID: "+r.ServerID().String())
	lines = append(lines, "  Capabilities: "+r.Capabilities().String())
	lines = append(lines, "  MaxTransactSize: "+strconv.Itoa(int(r.MaxTransactSize())))
	lines = append(lines, "  MaxReadSize: "+strconv.Itoa(int(r.MaxReadSize())))
	lines = append(lines, "  MaxWriteSize: "+strconv.Itoa(int(r.MaxWriteSize())))
	lines = append(lines, "  System Time: "+r.SystemTime().String())
	lines = append(lines, "  Server Start Time: "+r.ServerStartTime().String())
	lines = append(lines, "  Security Buffer Offset: "+strconv.Itoa(int(r.SecurityBufferOffset())))
	lines = append(lines, "  Security Buffer Length: "+strconv.Itoa(int(r.SecurityBufferLength())))
	lines = append(lines, "-------")
	return strings.Join(lines, "\n")
}
