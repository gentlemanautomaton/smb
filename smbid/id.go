package smbid

import "crypto/rand"

// ID is a 16-byte ephemeral universally unique identifier that uniquely
// identifies a client or server. Its bytes are stored in big-endian order.
type ID [16]byte

// New generates a random ID using crypto/rand.
func New() (id ID, err error) {
	// http://guid.one/guid/make

	// Grab 16 random bytes
	_, err = rand.Read(id[:])
	if err != nil {
		return
	}

	// Set the version number (4)
	id[6] &= 0x0f
	id[6] |= 0x40

	// Set the variant
	id[8] &= 0x3f
	id[8] |= 0x80

	return
}

// Read interprets a slice of bytes as a GUID in little endian byte order and
// copies the value to id. If v is less than 16 bytes long Read will panic.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40
func (id *ID) Read(v []byte) {
	_ = v[15] // bounds check hint to compiler; see golang.org/issue/14808

	// Data1: uint32
	id[3] = v[0]
	id[2] = v[1]
	id[1] = v[2]
	id[0] = v[3]

	// Data2: uint16
	id[5] = v[4]
	id[4] = v[5]

	// Data3: uint16
	id[7] = v[6]
	id[6] = v[7]

	// Data4: uint64
	id[15] = v[8]
	id[14] = v[9]
	id[13] = v[10]
	id[12] = v[11]
	id[11] = v[12]
	id[10] = v[13]
	id[9] = v[14]
	id[8] = v[15]
}

// Write writes id as a GUID in little endian byte order to v.
// If v is less than 16 bytes long Write will panic.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40
func (id ID) Write(v []byte) {
	_ = v[15] // Early bounds check to guarantee safety of writes below

	// Data1: uint32
	v[0] = id[3]
	v[1] = id[2]
	v[2] = id[1]
	v[3] = id[0]

	// Data2: uint16
	v[4] = id[5]
	v[5] = id[4]

	// Data3: uint16
	v[6] = id[7]
	v[7] = id[6]

	// Data4: uint64
	v[8] = id[15]
	v[9] = id[14]
	v[10] = id[13]
	v[11] = id[12]
	v[12] = id[11]
	v[13] = id[10]
	v[14] = id[9]
	v[15] = id[8]
}

// String returns a string representation of the ID.
func (id ID) String() string {
	var s [36]byte
	s[0], s[1] = hex(id[0])
	s[2], s[3] = hex(id[1])
	s[4], s[5] = hex(id[2])
	s[6], s[7] = hex(id[3])
	s[8] = '-'
	s[9], s[10] = hex(id[4])
	s[11], s[12] = hex(id[5])
	s[13] = '-'
	s[14], s[15] = hex(id[6])
	s[16], s[17] = hex(id[7])
	s[18] = '-'
	s[19], s[20] = hex(id[8])
	s[21], s[22] = hex(id[9])
	s[23] = '-'
	s[24], s[25] = hex(id[10])
	s[26], s[27] = hex(id[11])
	s[28], s[29] = hex(id[12])
	s[30], s[31] = hex(id[13])
	s[32], s[33] = hex(id[14])
	s[34], s[35] = hex(id[15])
	return string(s[:])
}

var digits = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

func hex(v byte) (high, low byte) {
	return digits[v>>4], digits[v&0x0f]
}
