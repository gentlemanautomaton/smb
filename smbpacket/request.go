package smbpacket

// Request interprets a slice of bytes as an SMB request packet.
type Request []byte

// Header returns the request header of r.
func (r Request) Header() RequestHeader {
	return RequestHeader(r[0:64])
}
