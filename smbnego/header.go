package smbnego

// headerSize is the number of bytes in an SMB packet header. It's defined
// here to avoid a dependency on smbpacket. It's needed by this package to
// calculate buffer offsets relative to the start of the packet.
const headerSize = 64
