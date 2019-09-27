package smbmultiproto

// Request interprets a slice of bytes as an SMB multi-protocol request
// packet compatible with SMB version 1.
type Request []byte

// Dialects returns the SMB2 dialects contained in the request.
//
// It returns nil if the request is invalid or does not contain an SMB
// multi-protocol negotiate command.
func (r Request) Dialects() []string {
	hdr := r.header()
	if !hdr.Valid() || !hdr.IsNegotiate() {
		return nil
	}
	return r.negotiate().Dialects()
}

// header returns the header of the request.
func (r Request) header() requestHeader {
	return requestHeader(r[0:32])
}

// negotiate interprets the request as a negotiate command.
func (r Request) negotiate() negotiate {
	return negotiate(r[32:])
}
