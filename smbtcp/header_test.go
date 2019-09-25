package smbtcp_test

import (
	"testing"

	"github.com/gentlemanautomaton/smb/smbtcp"
)

type HeaderTest struct {
	Bytes  []byte
	Valid  bool
	Length int
}

var headerTests = []HeaderTest{
	HeaderTest{[]byte{0, 255, 255, 255}, true, 16777215},
	HeaderTest{[]byte{0, 1, 0, 0}, true, 65536},
	HeaderTest{[]byte{0, 0, 1, 0}, true, 256},
	HeaderTest{[]byte{0, 0, 0, 1}, true, 1},
	HeaderTest{[]byte{0, 0, 0, 0}, true, 0},
	HeaderTest{[]byte{0, 0, 0}, false, 0},
	HeaderTest{[]byte{0, 0}, false, 0},
	HeaderTest{[]byte{0}, false, 0},
	HeaderTest{[]byte{}, false, 0},
	HeaderTest{[]byte{1, 0, 0, 0}, false, 0},
	HeaderTest{[]byte{64, 0, 1, 0}, false, 0},
	HeaderTest{[]byte{255, 255, 255, 255}, false, 0},
}

func TestHeader(t *testing.T) {
	for _, tt := range headerTests {
		h := smbtcp.Header(tt.Bytes)
		valid := h.Valid()
		if valid != tt.Valid {
			t.Errorf("Header(%v).Valid() = %v", tt.Bytes, valid)
		} else if valid {
			if length := h.Length(); length != tt.Length {
				t.Errorf("Header(%v).Length() = %d (want %d)", tt.Bytes, length, tt.Length)
			}
		}
	}
}
