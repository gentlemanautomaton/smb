package smbsequencer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gentlemanautomaton/smb"
	"github.com/gentlemanautomaton/smb/smbsequencer"
	"github.com/gentlemanautomaton/smb/smbserver"
)

type Action struct {
	Desc string
	F    func(t *testing.T, limit, action int, s smbserver.Sequencer)
}

func Credits(expected int) Action {
	return Action{
		Desc: fmt.Sprintf("Credits(%d)", expected),
		F: func(t *testing.T, limit, action int, s smbserver.Sequencer) {
			if credits := s.Credits(); credits != expected {
				t.Fatalf("Action[%d]: Credits(%d) got %d", action, expected, credits)
			}
		},
	}
}

func Expand(credits int) Action {
	return Action{
		Desc: fmt.Sprintf("Expand(%d)", credits),
		F: func(t *testing.T, limit, action int, s smbserver.Sequencer) {
			if !s.Expand(credits) {
				t.Fatalf("Action[%d]: Expand(%d) failed", action, credits)
			}
		},
	}
}

func ExpandFail(credits int) Action {
	return Action{
		Desc: fmt.Sprintf("ExpandFail(%d)", credits),
		F: func(t *testing.T, limit, action int, s smbserver.Sequencer) {
			if s.Expand(credits) {
				t.Fatalf("Action[%d]: ExpandFail(%d) succeeded", action, credits)
			}
		},
	}
}

func Consume(n smb.SeqNum) Action {
	return Action{
		Desc: fmt.Sprintf("Consume(%d)", n),
		F: func(t *testing.T, limit, action int, s smbserver.Sequencer) {
			if !s.Consume(n) {
				t.Fatalf("action %d: Consume %d failed", action, n)
			}
		},
	}
}

func ConsumeFail(n smb.SeqNum) Action {
	return Action{
		Desc: fmt.Sprintf("ConsumeFail(%d)", n),
		F: func(t *testing.T, limit, action int, s smbserver.Sequencer) {
			if s.Consume(n) {
				t.Fatalf("action %d: Consume %d succeeded", action, n)
			}
		},
	}
}

type SequencerTest []Action

func (s SequencerTest) String() string {
	parts := make([]string, 0, len(s))
	for _, action := range s {
		parts = append(parts, action.Desc)
	}
	return strings.Join(parts, ",")
}

var sequencerTests = []SequencerTest{
	SequencerTest{Credits(0)},
	SequencerTest{ConsumeFail(0), Credits(0)},
	SequencerTest{Expand(0), ConsumeFail(1), Credits(0)},
	SequencerTest{Expand(1), Consume(0), ConsumeFail(0), Credits(0)},
	SequencerTest{Expand(1), Credits(1), Consume(0), Credits(0)},
	SequencerTest{Expand(2), Consume(1), Credits(1)},
	SequencerTest{Expand(3), Consume(1), Credits(2)},
	SequencerTest{Expand(3), Consume(2), Consume(0), Credits(1)},
	SequencerTest{Expand(3), Consume(1), Consume(0), Consume(2), Credits(0)},
	SequencerTest{Expand(3), Consume(0), Credits(2)},
	SequencerTest{Expand(3), Credits(3), Consume(0), Credits(2), Consume(1), Credits(1), Consume(2), Credits(0)},
	SequencerTest{Expand(4), Consume(0), Credits(3)},
	SequencerTest{Expand(1), Consume(0), Expand(4), ConsumeFail(0), Consume(1), Consume(4), Credits(2), ConsumeFail(4), Consume(3), Expand(1), Credits(2), Consume(5), Consume(2), Credits(0)},
}

func TestSequencerActions(t *testing.T) {
	for _, test := range sequencerTests {
		t.Run(test.String(), func(t *testing.T) {
			const limit = 128
			s := smbsequencer.New(limit)
			for i, action := range test {
				action.F(t, limit, i, s)
			}
		})
	}
}

func TestSequencerSequential(t *testing.T) {
	s := smbsequencer.New(16)
	for i := 0; i < 32; i++ {
		if !s.Expand(1) {
			t.Fatalf("[%d]: expand(1) failed", i)
		}
		if credits := s.Credits(); credits != 1 {
			t.Fatalf("[%d]: credits = %d (want 1)", i, credits)
		}
		if !s.Consume(smb.SeqNum(i)) {
			t.Fatalf("[%d]: consume(%d) failed", i, i)
		}
		if credits := s.Credits(); credits != 0 {
			t.Fatalf("[%d]: credits = %d (want 0)", i, credits)
		}
	}
}

func TestSequencerExpandAll(t *testing.T) {
	for n := 1; n < 4096; n++ {
		s := smbsequencer.New(n)
		if !s.Expand(n) {
			t.Fatalf("[%d] expand(%d) failed", n, n)
		}
		for i := 0; i < n; i++ {
			if !s.Consume(smb.SeqNum(i)) {
				t.Fatalf("[%d] consume(%d) failed", n, i)
			}
		}
	}
}

func TestSequencerExpandOverflow(t *testing.T) {
	for i := 1; i < 512; i++ {
		s := smbsequencer.New(i)
		if !s.Expand(i) {
			t.Fatalf("[%d] expand(%d) failed", i, i)
		}
		if s.Expand(1) {
			t.Fatalf("[%d] overflow expansion succeeded", i)
		}
	}
}

func TestSequencerHalfFull(t *testing.T) {
	for limit := 2; limit < 512; limit++ {
		s := smbsequencer.New(limit)
		half := limit / 2
		if !s.Expand(half) {
			t.Fatalf("[%d] expand(%d) failed", limit, half)
		}
		for i := 0; i < limit*2; i++ {
			if !s.Expand(1) {
				t.Fatalf("[%d][%d] expand(1) failed", limit, i)
			}
			if !s.Consume(smb.SeqNum(i)) {
				t.Fatalf("[%d] consume(%d) failed", limit, i)
			}
		}
	}
}

func TestSequencerNearFull(t *testing.T) {
	limit := 128
	s := smbsequencer.New(limit)
	if !s.Expand(limit) {
		t.Fatalf("expand(%d) failed", limit)
	}
	n := 0
	for chunk := 1; chunk <= limit; chunk++ {
		for i := 0; i < limit*10; i += chunk {
			for c := chunk - 1; c >= 0; c-- {
				if !s.Consume(smb.SeqNum(n + c)) {
					t.Fatalf("[chunk %d] consume(%d) failed", chunk, n)
				}
			}
			if !s.Expand(chunk) {
				t.Fatalf("expand(%d) failed", chunk)
			}
			n += chunk
		}
	}
}

func BenchmarkSequencerSequential(b *testing.B) {
	const limit = 128
	s := smbsequencer.New(limit)
	next := smb.SeqNum(0)
	for n := 0; n < b.N; n++ {
		s.Expand(1)
		s.Consume(next)
		next++
	}
}

func BenchmarkSequencerBig(b *testing.B) {
	s := smbsequencer.New(b.N)
	s.Expand(b.N)
	for n := 0; n < b.N; n++ {
		s.Consume(smb.SeqNum(n))
	}
}

func BenchmarkSequencerExpand(b *testing.B) {
	const limit = 128
	s := smbsequencer.New(limit)
	next := smb.SeqNum(0)
	for n := 0; n < b.N; n++ {
		s.Expand(1)
		s.Consume(next)
		next++
	}
}
