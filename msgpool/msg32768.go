package msgpool

import "sync"

const size32768 = 32768

type msg32768 struct {
	length int
	pool   *sync.Pool
	data   [size32768]byte
}

func (msg *msg32768) Length() int {
	return msg.length
}

func (msg *msg32768) Bytes() []byte {
	return msg.data[0:msg.length]
}

func (msg *msg32768) Close() error {
	msg.pool.Put(msg)
	return nil
}
