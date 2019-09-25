package smbtcp

import "github.com/gentlemanautomaton/smb"

// MsgPool is a reusable pool of messages.
type MsgPool interface {
	Get(length int) smb.Message
}
