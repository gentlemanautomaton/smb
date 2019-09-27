package msgpool

import "sync"

const size4096 = 4096

type msg4096 struct {
	length int
	pool   *sync.Pool
	data   [size4096]byte
}

func (msg *msg4096) Length() int {
	return msg.length
}

func (msg *msg4096) Bytes() []byte {
	return msg.data[0:msg.length:msg.length]
}

func (msg *msg4096) Close() error {
	msg.pool.Put(msg)
	return nil
}

func (msg *msg4096) clear() {
	b := msg.Bytes()
	for i := range b {
		b[i] = 0
	}
}
