package smbsequencer

import (
	"github.com/gentlemanautomaton/smb"
)

// Sequencer keeps track of message sequence numbers for a connection.
// It must be created by calling New.
type Sequencer struct {
	limit   int // The maximum number of credits allowed
	credits int // The current number of outstanding credits

	capacity int // Total number of bits in the bitmap
	head     int // Head position (in bits)
	length   int // Allocated bits

	first smb.SeqNum // The sequence number of the head bit
	last  smb.SeqNum // The sequence number of the tail bit

	bits bitmap // A circular bitmap
}

// New returns a new sequencer without any credits.
// The maximum number of credits allowed will be constrained by limit.
func New(limit int) *Sequencer {
	size := (limit-1)/8 + 1
	s := &Sequencer{
		limit:    limit,
		capacity: size * 8,
		bits:     make(bitmap, size),
	}
	return s
}

// Credits returns the current number of credits allocated to the
// connection. This is the number of outstanding sequence numbers.
func (s *Sequencer) Credits() int {
	return s.credits
}

// Expand increases the number of outstanding sequence numbers for the
// connection by credits.
//
// If the expansion would cause the sequence numbers to wrap or a limit
// to be exceeded it returns false.
func (s *Sequencer) Expand(credits int) (ok bool) {
	// Check sequence number wrap (subtract to avoid wrapping in the test)
	if smb.MaxSeqNum-smb.SeqNum(credits) < s.last {
		return false
	}

	// Check credit limit
	if s.credits+credits > s.limit {
		return false
	}

	// Check buffer overflow
	if s.length+credits > s.capacity {
		return false
	}

	// Perform expansion
	for i := 0; i < credits; i++ {
		s.credits++
		s.add()
	}

	return true
}

// Consume removes the given sequence number from the list of outstanding
// sequence numbers.
//
// If the sequence number has already been consumed or is not outstanding
// it returns false.
func (s *Sequencer) Consume(n smb.SeqNum) (ok bool) {
	// Make sure n is in the expected range
	if n < s.first {
		return false
	}
	if n > s.last {
		return false
	}

	// Make sure n hasn't been received already
	pos := s.pos(n)
	if !s.bits.Value(pos) {
		return false
	}

	// Perform consumption
	s.credits--
	s.bits.Clear(pos)

	// Move the head as far forward as possible
	for s.length > 0 && !s.bits.Value(s.head) {
		s.remove()
	}

	return true
}

// add adds the next sequence number to the open set.
func (s *Sequencer) add() {
	s.length++
	s.last++
	tail := s.head + s.length - 1
	if tail >= s.capacity {
		tail -= s.capacity
	}
	s.bits.Set(tail)
	//fmt.Printf("add: %s, head: %d, length: %d, first: %d, credits: %d\n", s.bits, s.head, s.length, s.first, s.credits)
}

// remove removes the oldest sequence number from the open set.
func (s *Sequencer) remove() {
	s.length--
	s.first++
	s.head++
	if s.head >= s.capacity {
		s.head = 0
	}
	//fmt.Printf("rem: %s, head: %d, length: %d, first: %d, credits: %d\n", s.bits, s.head, s.length, s.first, s.credits)
}

// pos calculates the bit position of sequence number n.
func (s *Sequencer) pos(n smb.SeqNum) (pos int) {
	pos = int(n - s.first)
	pos += s.head
	if pos >= s.capacity {
		pos -= s.capacity
	}
	return
}
