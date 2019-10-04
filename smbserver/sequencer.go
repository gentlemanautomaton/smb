package smbserver

import "github.com/gentlemanautomaton/smb"

// A Sequencer keeps track of message sequence numbers for a connection.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dec8e905-9477-4c3f-bc64-b18d97c9f905
type Sequencer interface {
	// Credits returns the current number of credits allocated to the
	// connection. This is the number of outstanding sequence numbers.
	Credits() int

	// Expand increases the number of outstanding sequence numbers for the
	// connection by credits.
	//
	// If the expansion would cause the sequence numbers to wrap or a limit
	// to be exceeded it returns false.
	Expand(credits int) (ok bool)

	// Consume removes the given sequence number from the list of outstanding
	// sequence numbers.
	//
	// If the sequence number has already been consumed or is not outstanding
	// it returns false.
	Consume(n smb.SeqNum) (ok bool)
}
