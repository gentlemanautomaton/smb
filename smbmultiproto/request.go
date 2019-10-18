package smbmultiproto

import (
	"github.com/gentlemanautomaton/smb/smbdialect"
)

// Request interprets a slice of bytes as an SMB multi-protocol request
// packet compatible with SMB version 1.
type Request []byte

// Dialects returns the SMB2 dialects contained in the request.
//
// It returns nil if the request is invalid or does not contain an SMB
// multi-protocol negotiate command.
func (r Request) Dialects() smbdialect.List {
	if !r.Valid() {
		return nil
	}
	return r.negotiate().Dialects()
}

// Valid returns true if r is a valid SMB multi-protocol request.
func (r Request) Valid() bool {
	hdr := r.header()
	if !hdr.Valid() || !hdr.IsNegotiate() {
		return false
	}
	return true
}

// header returns the header of the request.
func (r Request) header() requestHeader {
	return requestHeader(r[0:32])
}

// negotiate interprets the request as a negotiate command.
func (r Request) negotiate() negotiate {
	return negotiate(r[32:])
}
