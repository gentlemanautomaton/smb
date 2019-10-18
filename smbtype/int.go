package smbtype

// Uint16 interprets a slice of 2 bytes as an integer in little-endian byte
// order and returns its value.
func Uint16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

// PutUint16 writes a uint16 as a slice of 2 bytes in little-endian byte
// order.
func PutUint16(b []byte, v uint16) {
	b[0], b[1] = byte(v), byte(v>>8)
}

// Uint32 interprets a slice of 4 bytes as an integer in little-endian byte
// order and returns its value.
func Uint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// PutUint32 writes a uint32 as a slice of 4 bytes in little-endian byte
// order.
func PutUint32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

// Uint64 interprets a slice of 8 bytes as an integer in little-endian byte
// order and returns its value.
func Uint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// PutUint64 writes a uint64 as a slice of 8 bytes in little-endian byte order.
func PutUint64(b []byte, v uint64) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	b[4], b[5], b[6], b[7] = byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56)
}
