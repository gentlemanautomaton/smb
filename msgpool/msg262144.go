package msgpool

import "sync"

const size262144 = 262144

type msg262144 struct {
	length int
	pool   *sync.Pool
	data   [size262144]byte
}

func (msg *msg262144) Length() int {
	return msg.length
}

func (msg *msg262144) Bytes() []byte {
	return msg.data[0:msg.length:msg.length]
}

func (msg *msg262144) Close() error {
	msg.pool.Put(msg)
	return nil
}
