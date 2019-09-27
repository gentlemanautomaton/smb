package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/gentlemanautomaton/smb/smbcommand"

	"github.com/gentlemanautomaton/signaler"
	"github.com/gentlemanautomaton/smb"
	"github.com/gentlemanautomaton/smb/smbmultiproto"
	"github.com/gentlemanautomaton/smb/smbpacket"
	"github.com/gentlemanautomaton/smb/smbserver"
	"github.com/gentlemanautomaton/smb/smbtcp"
)

func main() {
	shutdown := signaler.New().Capture(os.Interrupt, syscall.SIGTERM)
	defer shutdown.Trigger()

	address := ":445"
	listener, err := smbtcp.Listen(address)
	if err != nil {
		fmt.Printf("Failed to listen on %q: %v\n", address, err)
		os.Exit(1)
	}
	defer listener.Close()

	smbserver.Serve(listener, smbserver.HandlerFunc(func(conn smb.Conn) {
		remote := conn.RemoteAddr()
		negotiated := false
		for {
			if shutdown.Signaled() {
				return
			}

			msg, err := conn.Receive()
			if err != nil {
				fmt.Printf("Conn %s: %v\n", remote, err)
				return
			}

			if !negotiated {
				negotiated = negotiate(remote, msg)
			} else {
				process(remote, msg)
			}

			msg.Close()
		}
	}))
}

func negotiate(remote smb.Addr, msg smb.Message) bool {
	b := msg.Bytes()

	// SMB Multi-Protocol Negotation
	{
		dialects := smbmultiproto.Request(b).Dialects()
		if len(dialects) > 0 {
			fmt.Printf("Conn %s: Received SMB multi-protocol negotiate request for [%s] (%d bytes)\n", remote, strings.Join(dialects, ", "), msg.Length())
			// TODO: Send SMB2 Negotiate Response
			return true
		}
	}

	// SMB2 Protocol Negotation
	{
		request := smbpacket.Request(msg.Bytes())
		hdr := request.Header()
		if hdr.Valid() {
			if hdr.Command() == smbcommand.Negotiate {
				fmt.Printf("Conn %s: Received SMB2 negotiate request (%d bytes)\n", remote, msg.Length())
				// TODO: Send SMB2 Negotiate Response
				return true
			}
		}
	}

	return false
}

func process(remote smb.Addr, msg smb.Message) {
	request := smbpacket.Request(msg.Bytes())
	hdr := request.Header()
	if !hdr.Valid() {
		fmt.Printf("Conn %s: Received request with invalid header (%d bytes)\n", remote, msg.Length())
		return
	}
	fmt.Printf("Conn %s: Received %s request (%d bytes)\n", remote, hdr.Command(), msg.Length())
}
