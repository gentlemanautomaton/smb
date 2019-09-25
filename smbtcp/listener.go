package smbtcp

import (
	"net"

	"github.com/gentlemanautomaton/smb"
)

// Listener listens for SMB connections over TCP.
type Listener struct {
	tcpListener net.Listener
	pool        MsgPool
}

// NewListener returns an SMB listener that listens on l. Messages will be
// allocated from pool.
func NewListener(l net.Listener, pool MsgPool) Listener {
	return Listener{
		tcpListener: l,
		pool:        pool,
	}
}

// Accept waits for and returns the next SMB connection to the listener.
func (l Listener) Accept() (smb.Conn, error) {
	nc, err := l.tcpListener.Accept()
	if err != nil {
		return nil, err
	}
	return newConn(nc, l.pool), nil
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l Listener) Close() error {
	return l.tcpListener.Close()
}

// Addr returns the local address of the listener.
func (l Listener) Addr() smb.Addr {
	return l.tcpListener.Addr()
}
