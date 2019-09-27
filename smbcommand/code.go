package smbcommand

import "strconv"

// Code represents an SMB command code.
type Code uint16

// SMB command codes.
const (
	Negotiate      = 0x0000 // SMB2 NEGOTIATE
	SessionSetup   = 0x0001 // SMB2 SESSION_SETUP
	Logoff         = 0x0002 // SMB2 LOGOFF
	TreeConnect    = 0x0003 // SMB2 TREE_CONNECT
	TreeDisconnect = 0x0004 // SMB2 TREE_DISCONNECT
	Create         = 0x0005 // SMB2 CREATE
	Close          = 0x0006 // SMB2 CLOSE
	Flush          = 0x0007 // SMB2 FLUSH
	Read           = 0x0008 // SMB2 READ
	Write          = 0x0009 // SMB2 WRITE
	Lock           = 0x000A // SMB2 LOCK
	IOCTL          = 0x000B // SMB2 IOCTL
	Cancel         = 0x000C // SMB2 CANCEL
	Echo           = 0x000D // SMB2 ECHO
	QueryDirectory = 0x000E // SMB2 QUERY_DIRECTORY
	ChangeNotify   = 0x000F // SMB2 CHANGE_NOTIFY
	QueryInfo      = 0x0010 // SMB2 QUERY_INFO
	SetInfo        = 0x0011 // SMB2 SET_INFO
	OplockBreak    = 0x0012 // SMB2 OPLOCK_BREAK
)

// String returns a string representation of the command code.
func (c Code) String() string {
	switch c {
	case Negotiate:
		return "Negotiate"
	case SessionSetup:
		return "SessionSetup"
	case Logoff:
		return "Logoff"
	case TreeConnect:
		return "TreeConnect"
	case TreeDisconnect:
		return "TreeDisconnect"
	case Create:
		return "Create"
	case Close:
		return "Close"
	case Flush:
		return "Flush"
	case Read:
		return "Read"
	case Write:
		return "Write"
	case Lock:
		return "Lock"
	case IOCTL:
		return "IOCTL"
	case Cancel:
		return "Cancel"
	case Echo:
		return "Echo"
	case QueryDirectory:
		return "QueryDirectory"
	case ChangeNotify:
		return "ChangeNotify"
	case QueryInfo:
		return "QueryInfo"
	case SetInfo:
		return "SetInfo"
	case OplockBreak:
		return "OplockBreak"
	default:
		return "Command " + strconv.Itoa(int(c))
	}
}
