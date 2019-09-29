package smbdialect

import "strconv"

// Revision is an SMB dialect revision number.
type Revision uint16

// SMB dialect revision numbers.
const (
	SMB311   = 0x0311 // SMB 3.1.1
	SMB302   = 0x0302 // SMB 3.0.2
	SMB3     = 0x0300 // SMB 3.0
	SMB21    = 0x0210 // SMB 2.1
	SMB202   = 0x0202 // SMB 2.0.2
	Wildcard = 0x02FF // SMB 2.???
)

// String returns a string representation of the dialect revision number.
func (r Revision) String() string {
	switch r {
	case SMB311:
		return "SMB 3.1.1"
	case SMB302:
		return "SMB 3.0.2"
	case SMB3:
		return "SMB 3.0"
	case SMB21:
		return "SMB 2.1"
	case SMB202:
		return "SMB 2.0.2"
	case Wildcard:
		return "SMB 2.???"
	default:
		return "SMB " + strconv.Itoa(r.Major()) + "." + strconv.Itoa(r.Minor()) + "." + strconv.Itoa(r.Patch())
	}
}

// Major returns the major protocol revision number of r.
func (r Revision) Major() int {
	return int((r & 0xFF00) >> 8)
}

// Minor returns the minor protocol revision number of r.
func (r Revision) Minor() int {
	return int((r & 0x00F0) >> 4)
}

// Patch returns the patch protocol revision number of r.
func (r Revision) Patch() int {
	return int(r & 0x000F)
}
