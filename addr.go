package smb

// Addr is the network address of an SMB connection.
// It is compatible with net.Addr.
type Addr interface {
	Network() string
	String() string
}
