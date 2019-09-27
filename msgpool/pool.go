package msgpool

import (
	"sync"

	"github.com/gentlemanautomaton/smb"
)

// Pool is a pool of SMB messages that can be reused. It must be created with
// NewPool.
type Pool struct {
	p64     sync.Pool
	p512    sync.Pool
	p4096   sync.Pool
	p32768  sync.Pool
	p262144 sync.Pool
}

// New returns an SMB message pool that is ready for use.
func New() *Pool {
	var p Pool
	p = Pool{
		p64:     sync.Pool{New: func() interface{} { return &msg64{pool: &p.p64} }},
		p512:    sync.Pool{New: func() interface{} { return &msg512{pool: &p.p512} }},
		p4096:   sync.Pool{New: func() interface{} { return &msg4096{pool: &p.p4096} }},
		p32768:  sync.Pool{New: func() interface{} { return &msg32768{pool: &p.p32768} }},
		p262144: sync.Pool{New: func() interface{} { return &msg262144{pool: &p.p262144} }},
	}
	return &p
}

// Get returns a message of appropriate length from the pool with its bytes
// initialized to zero. The message must be closed when the caller is
// finished with it.
func (p *Pool) Get(length int) smb.Message {
	switch {
	case length <= size64:
		msg := p.p64.Get().(*msg64)
		msg.length = length
		msg.clear()
		return msg
	case length <= size512:
		msg := p.p512.Get().(*msg512)
		msg.length = length
		msg.clear()
		return msg
	case length <= size4096:
		msg := p.p4096.Get().(*msg4096)
		msg.length = length
		msg.clear()
		return msg
	case length <= size32768:
		msg := p.p32768.Get().(*msg32768)
		msg.length = length
		msg.clear()
		return msg
	case length <= size262144:
		msg := p.p262144.Get().(*msg262144)
		msg.length = length
		msg.clear()
		return msg
	default:
		return make(msgDynamic, 0, length)
	}
}
