package smbdialect

import "encoding/binary"

// List interprets a slice of bytes as an SMB dialect list.
type List []byte

// Count returns the number of dialects present in the list.
func (k List) Count() int {
	return len(k) / 2
}

// Member returns the member from the list at position i.
func (k List) Member(i int) Revision {
	i *= 2
	return Revision(binary.LittleEndian.Uint16(k[i : i+2]))
}

// Contains returns true if k contains r.
func (k List) Contains(r Revision) bool {
	count := k.Count()
	for i := 0; i < count; i++ {
		if k.Member(i) == r {
			return true
		}
	}
	return false
}
