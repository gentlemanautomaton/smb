package smbtype

import (
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// Unicode replacement character
	replacementChar = '\uFFFD'

	// Surrogate High (10 bits): 0xd800-0xdc00
	// Surrogate Low (10 bits):  0xdc00-0xe000
	surr1 = 0xd800
	surr2 = 0xdc00
	surr3 = 0xe000
)

// String interprets a slice of bytes as utf16 in little-endian byte order
// and returns its value as a string.
func String(b []byte) string {
	// Count how many bytes we'll need to store the string as utf8
	length := utf8Len(b)

	// Use a buffer of suitable size on the stack if possible
	const bufSize = 256
	var buf []byte
	switch {
	case length <= 32:
		var staticBuffer [32]byte
		buf = staticBuffer[:length]
	case length <= 256:
		var staticBuffer [256]byte
		buf = staticBuffer[:length]
	case length <= 4096:
		var staticBuffer [4096]byte
		buf = staticBuffer[:length]
	case length <= 65535:
		var staticBuffer [65535]byte
		buf = staticBuffer[:length]
	default:
		buf = make([]byte, length)
	}

	// Convert utf16 to utf8
	n := 0
	for i := 0; i+1 < len(b); {
		consumed, r := nextRune(b[i:])
		n += utf8.EncodeRune(buf[n:], r)
		i += consumed
	}

	return string(buf)
}

// utf8Len returns the number of bytes needed to represent a utf16 string as
// utf8.
func utf8Len(b []byte) (length int) {
	for i := 0; i+1 < len(b); {
		consumed, r := nextRune(b[i:])
		encodeLen := utf8.RuneLen(r)
		if encodeLen == -1 {
			length += utf8.RuneLen(replacementChar)
		} else {
			length += encodeLen
		}
		i += consumed
	}
	return
}

func nextRune(b []byte) (consumed int, r rune) {
	switch r1 := binary.LittleEndian.Uint16(b); {
	case isNormalRune(r1):
		return 2, rune(r1)
	case isSurrogateHigh(r1) && 3 < len(b):
		// Surrogate sequence
		if r2 := binary.LittleEndian.Uint16(b[2:]); isSurrogateLow(r2) {
			return 4, utf16.DecodeRune(rune(r1), rune(r2))
		}
		fallthrough
	default:
		// Invalid surrogate sequence
		return 2, replacementChar
	}
}

func isNormalRune(r uint16) bool {
	return r < surr1 || surr3 <= r
}

func isSurrogateHigh(r uint16) bool {
	return surr1 <= r && r < surr2
}

func isSurrogateLow(r uint16) bool {
	return surr2 <= r && r < surr3
}
