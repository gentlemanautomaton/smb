package smbtcp

import (
	"errors"
	"io"
	"net"

	"github.com/gentlemanautomaton/smb"
)

// Conn is an SMB connection over TCP.
type Conn struct {
	nc      net.Conn
	msgPool MsgPool
}

func newConn(nc net.Conn, msgPool MsgPool) Conn {
	return Conn{
		nc:      nc,
		msgPool: msgPool,
	}
}

// MaxLength returns the maximum message size for the connection.
func (c Conn) MaxLength() int {
	return MaxLength
}

// Receive receives a message from the connection.
//
// TODO: Support deadlines and/or cancellation.
func (c Conn) Receive() (smb.Message, error) {
	var buf [4]byte
	if _, err := io.ReadAtLeast(c.nc, buf[:], 4); err != nil {
		return nil, err
	}
	hdr := Header(buf[:])
	if !hdr.Valid() {
		return nil, ErrBadHeader
	}
	msg := c.msgPool.Get(hdr.Length())
	if _, err := io.ReadAtLeast(c.nc, msg.Bytes(), msg.Length()); err != nil {
		return nil, err
	}
	return msg, nil
}

// Send sends a message to the connection.
//
// TODO: Support deadlines and/or cancellation.
func (c Conn) Send(smb.Message) error {
	return errors.New("smbtcp.Conn.Send() is not yet implemented")
}

// Close closes the connection.
// Any blocked Receive or Send operations will be unblocked and return errors.
func (c Conn) Close() error {
	return c.nc.Close()
}

// LocalAddr returns the local address of the connection.
func (c Conn) LocalAddr() smb.Addr {
	return c.nc.LocalAddr()
}

// RemoteAddr returns the remote address of the connection.
func (c Conn) RemoteAddr() smb.Addr {
	return c.nc.RemoteAddr()
}
