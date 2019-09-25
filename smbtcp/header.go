package smbtcp

import "errors"

// MaxLength is the maximum message length when using direct TCP transport.
const MaxLength = 16777215

// ErrBadHeader is returned when an invalid transport packet header is
// received from a connection.
var ErrBadHeader = errors.New("bad smb2 tcp header")

// Header interprets the bytes of a transport packet header for messages sent
// over TCP.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1dfacde4-b5c7-4494-8a14-a09d3ab4cc83
type Header []byte

//  type Header struct {
//  	Zero                 byte    // Must always be zero
//  	StreamProtocolLength [3]byte // Network byte order
//  }

// Valid returns true if h is valid. It tests the length of h and the value of
// its zero byte.
func (h Header) Valid() bool {
	if len(h) < 4 {
		return false
	}
	if h[0] != 0 {
		return false
	}
	return true
}

// Length returns the stream protocol length of h. If h is not valid it may
// panic.
func (h Header) Length() int {
	// Return h[1:4] as a 3 byte integer in network byte order
	return (int(h[1]) << 16) | (int(h[2]) << 8) | int(h[3])
}
