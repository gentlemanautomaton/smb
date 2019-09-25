package smbserver

import (
	"net"
	"time"

	"github.com/gentlemanautomaton/smb"
)

// Server responds to SMB connection requests.
type Server struct {
	handler Handler
}

// New retursn
func New(h Handler) *Server {
	return &Server{
		handler: h,
	}
}

// Serve starts serving connections on l with the given handler.
func Serve(l smb.Listener, handler Handler) error {
	s := New(handler)
	return s.Serve(l)
}

// Serve causes s to start serving connections on l.
func (s Server) Serve(l smb.Listener) error {
	var sleep time.Duration // Sleep duration between failures
	for {
		conn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				sleep = nextDelay(sleep)
				time.Sleep(sleep)
				continue
			}
			return err
		}
		sleep = 0 // Reset on success
		go s.serve(conn)
	}
}

func (s Server) serve(conn smb.Conn) {
	s.handler.ServeSMB(conn)
}

func nextDelay(last time.Duration) (next time.Duration) {
	if last == 0 {
		next = 5 * time.Millisecond
	} else {
		next = last * 2
	}
	const max = 1 * time.Second
	if next > max {
		next = max
	}
	return
}
