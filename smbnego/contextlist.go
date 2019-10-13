package smbnego

// ContextOffset defines the offset of a context within a negotiation context
// list.
type ContextOffset uint

// ContextList interprets a slice of bytes as an SMB negotiation context list.
type ContextList []byte

// Valid returns true if the negotiation context list has the expected number
// of valid contexts.
func (k ContextList) Valid(count uint16) bool {
	var (
		listLength = ContextOffset(len(k))
		start      = ContextOffset(0)
	)
	for i := uint16(0); i < count; i++ {
		end := start + ContextHeaderLength
		if end > listLength {
			return false
		}
		ctx := Context(k[start:end:end])
		length := ContextOffset(ctx.Length())
		end = start + length
		if end > listLength {
			return false
		}
		// TODO: Validate each individual context?
		start = end
	}
	return true
}

// Member returns the context at the given offset within the list.
func (k ContextList) Member(offset ContextOffset) Context {
	end := k.Next(offset)
	return Context(k[offset:end:end])
}

// Next returns the offset of the next member within the list after last.
func (k ContextList) Next(last ContextOffset) (next ContextOffset) {
	end := last + ContextHeaderLength
	ctx := Context(k[last:end:end])
	return last + ContextOffset(ctx.Length())
}
