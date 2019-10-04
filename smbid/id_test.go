package smbid_test

import (
	"bytes"
	"testing"

	"github.com/gentlemanautomaton/smb/smbid"
)

type Test struct {
	Bytes  []byte
	ID     smbid.ID
	String string
}

var tests = []Test{
	Test{
		[]byte{0xae, 0x4f, 0x1d, 0xf8, 0xec, 0x7d, 0xd0, 0x11, 0xf6, 0x6b, 0x1e, 0xc9, 0xa0, 0x00, 0x65, 0xa7},
		smbid.ID{0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e, 0x6b, 0xf6},
		"f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
	},
	Test{
		[]byte{0x3d, 0xdb, 0x0a, 0x20, 0xf4, 0xb3, 0xde, 0x4b, 0x30, 0xbe, 0xd6, 0x88, 0x68, 0x2c, 0xc8, 0xa9},
		smbid.ID{0x20, 0x0a, 0xdb, 0x3d, 0xb3, 0xf4, 0x4b, 0xde, 0xa9, 0xc8, 0x2c, 0x68, 0x88, 0xd6, 0xbe, 0x30},
		"200adb3d-b3f4-4bde-a9c8-2c6888d6be30",
	},
}

func TestNew(t *testing.T) {
	var zero smbid.ID
	for i := 0; i < 32; i++ {
		id, err := smbid.New()
		if err != nil {
			t.Fatal(err)
		}
		if id == zero {
			t.Fatalf("smbid.New returned a zeroed id")
		}
	}
}

func TestReadWriteString(t *testing.T) {
	for i, test := range tests {
		// Read test
		{
			var id smbid.ID
			id.Read(test.Bytes)
			if id != test.ID {
				t.Errorf("test %d: read failure", i)
			}
		}

		// Write test
		{
			var buf [16]byte
			id := test.ID
			id.Write(buf[:])
			if !bytes.Equal(buf[:], test.Bytes) {
				t.Errorf("test %d: write failure", i)
			}
		}

		// String test
		if s := test.ID.String(); s != test.String {
			t.Errorf("test %d: string failure: %s (want %s)", i, s, test.String)
		}
	}
}

func BenchmarkRead(b *testing.B) {
	const count = 1048576
	buf := make([]byte, count*16)
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	b.ResetTimer()
	i := 0
	for n := 0; n < b.N; n++ {
		var id smbid.ID
		pos := i * 16
		id.Read(buf[pos : pos+16])
		i++
		if i >= count {
			i = 0
		}
	}
}

func BenchmarkString(b *testing.B) {
	const count = 1048576
	buf := make([]byte, count*16)
	out := make([]string, count)
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	b.ResetTimer()
	i := 0
	for n := 0; n < b.N; n++ {
		var id smbid.ID
		pos := i * 16
		id.Read(buf[pos : pos+16])
		out[i] = id.String()
		i++
		if i >= count {
			i = 0
		}
	}
}
