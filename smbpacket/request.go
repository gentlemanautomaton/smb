package smbpacket

// Request interprets a slice of bytes as an SMB request packet.
type Request []byte

// Header returns the request header of r.
func (r Request) Header() RequestHeader {
	return RequestHeader(r[0:HeaderSize])
}

// Data returns the request data that follows the header.
func (r Request) Data() []byte {
	if len(r) <= HeaderSize {
		return nil
	}
	return r[HeaderSize:]
}
