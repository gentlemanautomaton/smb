package smb

// Conn is an SMB connection.
type Conn interface {
	// Receive receives a message from the connection.
	//
	// TODO: Support deadlines and/or cancellation.
	Receive() (Message, error)

	// Send sends a message to the connection.
	//
	// TODO: Support deadlines and/or cancellation.
	Send(Message) error

	// Close closes the connection.
	// Any blocked Receive or Send operations will be unblocked and return
	// errors.
	Close() error

	// LocalAddr returns the local network address.
	LocalAddr() Addr

	// RemoteAddr returns the remote network address.
	RemoteAddr() Addr
}
