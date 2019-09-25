package smbtcp

import (
	"net"

	"github.com/gentlemanautomaton/smb"
	"github.com/gentlemanautomaton/smb/msgpool"
)

// Listen starts listening for SMB messages over TCP at the given address.
func Listen(address string) (smb.Listener, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return NewListener(l, msgpool.New()), nil
}
