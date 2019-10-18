package smbdialect

// Uninitialized is the starting dialect negotiation state.
const Uninitialized State = 0xFFFF

// State holds the SMB dialect negotiation state for a connection. It holds
// values for the Connection.NegotiateDialect variable in the SMB protocol.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8
type State Revision

// CanTransition returns true if s can transition to next.
func (s State) CanTransition(next State) (ok bool) {
	switch s {
	case Uninitialized:
		switch next {
		case SMB311, SMB302, SMB3, SMB21, SMB202, Wildcard:
			return true
		default:
			return false
		}
	case Wildcard:
		switch next {
		case SMB311, SMB302, SMB3, SMB21, SMB202:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// Revision returns the SMB dialect revision currently negotiated by s.
func (s State) Revision() Revision {
	return Revision(s)
}

// Ready returns true if s is in a completed negotiation
func (s State) Ready() bool {
	switch s {
	case SMB311, SMB302, SMB3, SMB21, SMB202:
		return true
	default:
		return false
	}
}

// String returns a string representation of the dialect state.
func (s State) String() string {
	return Revision(s).String()
}
