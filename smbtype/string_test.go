package smbtype_test

import (
	"encoding/binary"
	"strconv"
	"testing"
	"unicode/utf16"

	"github.com/gentlemanautomaton/smb/smbtype"
)

type stringTest struct {
	String string
	Bytes  []byte
}

func makeStringTest(s string) stringTest {
	points := utf16.Encode([]rune(s))
	b := make([]byte, len(points)*2)
	for i, point := range points {
		binary.LittleEndian.PutUint16(b[i*2:], point)
	}
	return stringTest{
		String: s,
		Bytes:  b,
	}
}

var stringTests = [...]stringTest{
	makeStringTest(""),
	makeStringTest("Hello World"),
	makeStringTest("Some centaurs saw some saucers."),
	makeStringTest("Finally! My comeuppance has arrived! I should go wait somewhere inconspicuous and act none the wiser."),
	makeStringTest("日本語"),
	makeStringTest("Hello, 世界"),
	makeStringTest("⌘"),
	makeStringTest("C𝄡F:𝄢G  𝄞"),
	makeStringTest("Koala"),
}

func TestString(t *testing.T) {
	for _, tt := range stringTests {
		s := smbtype.String(tt.Bytes)
		if s != tt.String {
			t.Errorf("String(%x) = %s; want %s", tt.Bytes, s, tt.String)
		}
	}
}

type stringBenchmark struct {
	Name string
	stringTest
}

func makeStringBenchmark(name, value string) stringBenchmark {
	return stringBenchmark{
		Name:       name,
		stringTest: makeStringTest(value),
	}
}

func makeName(length int) string {
	const raw = `Some centaurs saw some saucers.`
	b := make([]byte, length)
	n := 0
	for i := 0; i < length; i++ {
		if n >= len(raw) {
			n = 0
		}
		b[i] = raw[n]
	}
	return string(b)
}

func makeBenchmarks() (benchmarks []stringBenchmark) {
	chunk := 4
	size := 0
	i := 1
	for size <= 65535 {
		bench := makeStringBenchmark("size-"+strconv.Itoa(size), makeName(size))
		benchmarks = append(benchmarks, bench)
		size += chunk
		chunk *= 4
		i++
	}
	return
}

func BenchmarkString(b *testing.B) {
	for _, bench := range makeBenchmarks() {
		b.Run("smbtype-"+bench.Name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				smbtype.String(bench.Bytes)
			}
		})
		b.Run("stdlib-"+bench.Name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				stdlibString(bench.Bytes)
			}
		})
	}
}

// Benchmarks using the standard library for comparison

func stdlibString(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u[i/2] = binary.LittleEndian.Uint16(b[i:])
	}
	return string(utf16.Decode(u))
}
