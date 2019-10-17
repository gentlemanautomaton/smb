package smbpacket

// SMB2 is the SMB version 2 and 3 protocol packet identifier.
var SMB2 = Protocol{0xFE, 'S', 'M', 'B'}

// Protocol is an SMB packet protocol identifier.
type Protocol [4]byte
