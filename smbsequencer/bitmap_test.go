package smbsequencer

import (
	"testing"
)

func TestBitmap(t *testing.T) {
	for size := 1; size <= 42; size++ {
		b := make(bitmap, size)
		for i := 0; i < size*8; i++ {
			if b.Value(i) {
				t.Fail()
				return
			}
			b.Set(i)
			if !b.Value(i) {
				t.Fail()
				return
			}
			b.Clear(i)
			if b.Value(i) {
				t.Fail()
				return
			}
		}
	}
}

func TestBitmapString(t *testing.T) {
	type bitmapTest struct {
		Bits     bitmap
		Expected string
	}
	tests := []bitmapTest{
		{bitmap{1}, "10000000"},
		{bitmap{1 << 1}, "01000000"},
		{bitmap{1 << 2}, "00100000"},
		{bitmap{1 << 3}, "00010000"},
		{bitmap{1 << 4}, "00001000"},
		{bitmap{1 << 5}, "00000100"},
		{bitmap{1 << 6}, "00000010"},
		{bitmap{1 << 7}, "00000001"},
		{bitmap{0, 1}, "0000000010000000"},
		{bitmap{0, 1 << 1}, "0000000001000000"},
		{bitmap{0, 1 << 2}, "0000000000100000"},
		{bitmap{0, 1 << 3}, "0000000000010000"},
		{bitmap{0, 1 << 4}, "0000000000001000"},
		{bitmap{0, 1 << 5}, "0000000000000100"},
		{bitmap{0, 1 << 6}, "0000000000000010"},
		{bitmap{0, 1 << 7}, "0000000000000001"},
		{bitmap{1, 1}, "1000000010000000"},
	}
	for i, test := range tests {
		if result := test.Bits.String(); result != test.Expected {
			t.Errorf("test %d: %s (want %s)", i, result, test.Expected)
		}
	}
}
