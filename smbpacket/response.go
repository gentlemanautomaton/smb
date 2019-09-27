package smbpacket

// Response interprets a slice of bytes of an SMB response packet.
type Response []byte

// Header returns the response header of r.
func (r Response) Header() ResponseHeader {
	return ResponseHeader(r[0:64])
}
