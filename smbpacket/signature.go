package smbpacket

// Signature is an SMB packet signature.
type Signature [16]byte

// Unmarshal copies the first 16 bytes of v into s.
func (s *Signature) Unmarshal(v []byte) {
	s[0], s[1], s[2], s[3] = v[0], v[1], v[2], v[3]
	s[4], s[5], s[6], s[7] = v[4], v[5], v[6], v[7]
	s[8], s[9], s[10], s[11] = v[8], v[9], v[10], v[11]
	s[12], s[13], s[14], s[15] = v[12], v[13], v[14], v[15]
}

// Marshal copies 16 bytes of signature data into v.
func (s Signature) Marshal(v []byte) {
	v[0], v[1], v[2], v[3] = s[0], s[1], s[2], s[3]
	v[4], v[5], v[6], v[7] = s[4], s[5], s[6], s[7]
	v[8], v[9], v[10], v[11] = s[8], s[9], s[10], s[11]
	v[12], v[13], v[14], v[15] = s[12], s[13], s[14], s[15]
}
