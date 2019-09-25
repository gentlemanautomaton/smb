package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/gentlemanautomaton/signaler"
	"github.com/gentlemanautomaton/smb"
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
		for {
			if shutdown.Signaled() {
				return
			}
			msg, err := conn.Receive()
			if err != nil {
				fmt.Printf("Conn %s: %v\n", conn.RemoteAddr(), err)
				return
			}
			fmt.Printf("Conn %s: Received message of length %d\n", conn.RemoteAddr(), msg.Length())
		}
	}))
}
