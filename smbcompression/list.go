package smbcompression

import "encoding/binary"

// List interprets a slice of bytes as an SMB compression algorithm list.
type List []byte

// Count returns the number of algorithms present in the list.
func (k List) Count() int {
	return len(k) / 2
}

// Member returns the list member at position i.
func (k List) Member(i int) Algorithm {
	i *= 2
	return Algorithm(binary.LittleEndian.Uint16(k[i : i+2]))
}

// Contains returns true if the list contains a.
func (k List) Contains(a Algorithm) bool {
	count := k.Count()
	for i := 0; i < count; i++ {
		if k.Member(i) == a {
			return true
		}
	}
	return false
}
