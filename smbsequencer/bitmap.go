package smbsequencer

type bitmap []byte

func (b bitmap) Set(bit int) {
	index, bit := bit/8, bit%8
	b[index] |= 1 << uint(bit)
}

func (b bitmap) Clear(bit int) {
	index, bit := bit/8, bit%8
	b[index] &^= 1 << uint(bit)
}

func (b bitmap) Value(bit int) bool {
	index, bit := bit/8, bit%8
	return (b[index] & (1 << uint(bit))) != 0
}

func (b bitmap) String() string {
	capacity := len(b) * 8
	str := make([]byte, capacity)
	for i := 0; i < capacity; i++ {
		if val := b.Value(i); val {
			str[i] = '1'
		} else {
			str[i] = '0'
		}
	}
	return string(str)
}
