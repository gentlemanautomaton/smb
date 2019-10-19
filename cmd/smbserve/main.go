package main

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/gentlemanautomaton/signaler"
	"github.com/gentlemanautomaton/smb/smbcommand"
	"github.com/gentlemanautomaton/smb/smbdialect"
	"github.com/gentlemanautomaton/smb/smbid"
	"github.com/gentlemanautomaton/smb/smbmultiproto"
	"github.com/gentlemanautomaton/smb/smbpacket"
	"github.com/gentlemanautomaton/smb/smbproto"
	"github.com/gentlemanautomaton/smb/smbsecmode"
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

	id, err := smbid.New()
	if err != nil {
		fmt.Printf("Failed to generate server ID: %v\n", err)
		os.Exit(2)
	}

	smbserver.Serve(listener, id, smbserver.HandlerFunc(func(conn smbserver.Conn) {
		remote := conn.RemoteAddr()
		if err != nil {
			panic(err)
		}
		for {
			if shutdown.Signaled() {
				return
			}

			msg, err := conn.Receive()
			if err != nil {
				fmt.Printf("Conn %s: %v\n", remote, err)
				return
			}

			ok := func() bool {
				defer msg.Close()

				b := msg.Bytes()
				request := smbpacket.Request(msg.Bytes())
				hdr := request.Header()
				if !hdr.Valid() {
					if conn.Dialect.Ready() {
						fmt.Printf("Conn %s: Received request with invalid header (%d bytes)\n", remote, msg.Length())
						return false
					}

					// SMB Multi-Protocol Negotation
					request := smbmultiproto.Request(b)
					if !request.Valid() {
						fmt.Printf("Conn %s: Received request with invalid header (%d bytes)\n", remote, msg.Length())
						return false
					}

					dialects := request.Dialects()
					var next smbdialect.State
					switch {
					case dialects.Contains(smbdialect.Wildcard):
						next = smbdialect.Wildcard
						conn.SupportMultiCredit = true
					case dialects.Contains(smbdialect.SMB202):
						next = smbdialect.SMB202
					default:
						return false
					}

					if !conn.Dialect.CanTransition(next) {
						return false
					}

					fmt.Printf("Conn %s: Received SMB multi-protocol negotiate request for %s (%d bytes)\n", remote, next, msg.Length())

					conn.Dialect = next

					conn.MaxTransactSize = 8388608
					conn.MaxReadSize = 8388608
					conn.MaxWriteSize = 8388608

					conn.Expand(1)
					conn.Marshal(0, 1, smbproto.NegotiateResponse{
						SecMode:         smbsecmode.SigningEnabled,
						Dialect:         conn.Dialect.Revision(),
						Server:          conn.Server,
						MaxTransactSize: conn.MaxTransactSize,
						MaxReadSize:     conn.MaxReadSize,
						MaxWriteSize:    conn.MaxWriteSize,
						SystemTime:      time.Now(),
					})
					return true
				}

				fmt.Printf("Conn %s: Received SMB2 %s (%d bytes)\n", remote, hdr.Command(), msg.Length())

				if !conn.Dialect.Ready() {
					if hdr.Command() == smbcommand.Negotiate {
						// TODO: Send SMB2 Negotiate Response
						//return true
						return false
					}

					return false
				}

				//handle(request, hdr)
				return false
			}()
			if !ok {
				fmt.Printf("Conn %s: Server initiated connection close.\n", remote)
				return
			}
		}
	}))
}

func handle(request smbpacket.Request, hdr smbpacket.RequestHeader) {
	switch hdr.Command() {
	case smbcommand.Create:
		// TODO: Handle create
		return
	case smbcommand.Cancel:
		// TODO: Handle cancel
		return
	}
	// TODO: Handle invalid or unexpected request
}
