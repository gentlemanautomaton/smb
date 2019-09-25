package msgpool

type msgDynamic []byte

func (msg msgDynamic) Length() int {
	return len(msg)
}

func (msg msgDynamic) Bytes() []byte {
	return []byte(msg)
}

func (msg msgDynamic) Close() error {
	return nil
}
