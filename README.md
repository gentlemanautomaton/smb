smb [![GoDoc](https://godoc.org/github.com/gentlemanautomaton/smb?status.svg)](https://godoc.org/github.com/gentlemanautomaton/smb)
====

This is a work-in-progress implementation of a Server Message Block protocol
library. It supports protocol versions 2 and 3. It is written entirely in Go.
It is not yet suitable for use.

Design Goals
----

1. Provide an SMB library that can be used to write an SMB server.
2. Make it as easy to write an SMB server with this library as it is to write an HTTP server with the standard library. 
3. Make the design composable so that many aspects of protocol handling can be customized, instrumented and experimented with.
4. Follow Go language conventions and idioms whenever possible.
5. Avoid external dependencies.

Security Goals
----

1. Support the highest levels of data integrity and privacy afforded by the specification.
2. Don't support NTLM.
3. Avoid the unsafe package.
4. Facilitate creation of servers that *only* support encrypted traffic.

Performance Goals
---

1. Make the implementation fast, but don't sacrifice security to do so.
2. Minimize byte copying.
3. Minimize memory allocation and garbage collection.
4. Avoid the reflect package.

Feature Goals
----

1. Support SMB version 3.1.1.
2. Support Kerberos for session authentication. Facilitate use of out-of-library implementations of Kerberos.
3. Support the TCP transport.
4. Support encryption.

Pie-in-the-sky Goals
----

1. Tests cover more than 95% of the code.
2. Zero memory allocations when in steady state operation under consistent load.
3. Support the QUIC transport if and when it's ready in a future protocol release.

Non-Goals
----

1. Support SMB version 1 and/or CIFS.  If it's not implemented it can't be used by accident.

Message Processing
----

A lovely feature of Go is its support for strongly typed byte slices:

```Go
package smbpacket

// Request interprets a slice of bytes as an SMB request packet.
type Request []byte

// Valid returns true if r is long enough to include a request header.
func (r Request) Valid() bool {
	if len(r) < 64 {
		return false
	}
	return true
}

// Header returns the request header of r.
func (r Request) Header() RequestHeader {
	return RequestHeader(r[0:64])
}
```

This library relies on typed byte slices extensively to interpret buffered
messages:

```Go
func handle(msg smb.Message) {
	b := msg.Bytes()
	if request := smbpacket.Request(b); request.Valid() {
		if hdr := request.Header(); hdr.Valid() {
			switch hdr.Command() {
			case smbcommand.Create:
				// TODO: Handle create
				return
			case smbcommand.Cancel:
				// TODO: Handle cancel
				return
			}
		}
	}
	// TODO: Handle invalid or unexpected request
}
```

Byte ordering is handled by the accessors for each byte slice:

```Go
package smbpacket

// RequestHeader interprets a slice of bytes as an SMB request packet header.
type RequestHeader []byte

// ...

// Command returns the command code of the request.
func (h RequestHeader) Command() smbcommand.Code {
	return smbcommand.Code(binary.LittleEndian.Uint16(h[12:14]))
}
```

This approach has several benefits:

1. Go performs slice boundary checks as necessary, increasing safety.
2. Messages can be interpreted without allocating data on the heap, improving performance.
3. Message fields are interpreted lazily, improving performance.