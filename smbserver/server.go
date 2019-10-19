package smbserver

import (
	"net"
	"time"

	"github.com/gentlemanautomaton/smb"
	"github.com/gentlemanautomaton/smb/smbdialect"
	"github.com/gentlemanautomaton/smb/smbid"
	"github.com/gentlemanautomaton/smb/smbsequencer"
)

// Server responds to SMB connection requests.
type Server struct {
	handler Handler
	id      smbid.ID
}

// New returns a new SMB server with message handler h.
func New(id smbid.ID, h Handler) *Server {
	return &Server{
		handler: h,
		id:      id,
	}
}

// Serve starts serving connections on l with the given handler.
func Serve(l smb.Listener, id smbid.ID, handler Handler) error {
	s := New(id, handler)
	return s.Serve(l)
}

// Serve causes s to start serving connections on l.
func (s Server) Serve(l smb.Listener) error {
	var sleep time.Duration // Sleep duration between receive failures
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

func (s Server) serve(transport smb.Conn) {
	defer transport.Close()
	s.handler.ServeSMB(Conn{
		Conn:      transport,
		Sequencer: smbsequencer.New(128),
		ConnState: ConnState{
			Dialect:      smbdialect.Uninitialized,
			CreationTime: time.Now(),
		},
		GlobalState: GlobalState{
			Server: s.id,
		},
	})
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
