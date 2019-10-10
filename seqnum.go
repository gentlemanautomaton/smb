package smb

// MaxSeqNum is the maximum valid sequence number.
const MaxSeqNum = ^SeqNum(0)

// SeqNum is an SMB message sequence number.
type SeqNum uint64
