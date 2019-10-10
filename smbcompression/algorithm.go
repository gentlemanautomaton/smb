package smbcompression

import "strconv"

// Algorithm identifies a type of compression algorithm.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271
type Algorithm uint16

// Possible compression algorithms.
const (
	None        = 0x0000
	LZNT1       = 0x0001
	LZ77        = 0x0002
	LZ77Huffman = 0x0003
)

// String returns a string representation of the compression algorithm.
func (a Algorithm) String() string {
	switch a {
	case None:
		return "None"
	case LZNT1:
		return "LZNT1"
	case LZ77:
		return "LZ77"
	case LZ77Huffman:
		return "LZ77+Huffman"
	default:
		return "Compression-" + strconv.Itoa(int(a))
	}
}
