package msgpool

import "sync"

const size64 = 64

type msg64 struct {
	length int
	pool   *sync.Pool
	data   [size64]byte
}

func (msg *msg64) Length() int {
	return msg.length
}

func (msg *msg64) Bytes() []byte {
	return msg.data[0:msg.length:msg.length]
}

func (msg *msg64) Close() error {
	msg.pool.Put(msg)
	return nil
}
