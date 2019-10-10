package smbencryption

import "encoding/binary"

// List interprets a slice of bytes as an SMB encryption cipher list.
type List []byte

// Count returns the number of ciphers present in the list.
func (k List) Count() int {
	return len(k) / 2
}

// Member returns the list member at position i.
func (k List) Member(i int) Cipher {
	i *= 2
	return Cipher(binary.LittleEndian.Uint16(k[i : i+2]))
}

// Contains returns true if the list contains c.
func (k List) Contains(c Cipher) bool {
	count := k.Count()
	for i := 0; i < count; i++ {
		if k.Member(i) == c {
			return true
		}
	}
	return false
}
