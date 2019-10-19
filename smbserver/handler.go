package smbserver

// A Handler handles SMB connections.
type Handler interface {
	ServeSMB(Conn)
}

// HandlerFunc is a function that can act as a Handler.
type HandlerFunc func(c Conn)

// ServeSMB handles the given SMB connection.
func (h HandlerFunc) ServeSMB(c Conn) {
	h(c)
}
