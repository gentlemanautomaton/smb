package msgpool

import "sync"

const size512 = 512

type msg512 struct {
	length int
	pool   *sync.Pool
	data   [size512]byte
}

func (msg *msg512) Length() int {
	return msg.length
}

func (msg *msg512) Bytes() []byte {
	return msg.data[0:msg.length:msg.length]
}

func (msg *msg512) Close() error {
	msg.pool.Put(msg)
	return nil
}

func (msg *msg512) clear() {
	b := msg.Bytes()
	for i := range b {
		b[i] = 0
	}
}
