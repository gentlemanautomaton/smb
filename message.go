package smb

// Message is a buffered SMB message that can be sent and received by
// a connection.
type Message interface {
	// Length returns the length of the message in bytes.
	Length() int

	// Bytes returns a slice of bytes from the message.
	Bytes() []byte

	// Close releases any resources consumed by the message. If the message
	// came from a message pool it returns the message to the pool.
	Close() error
}
