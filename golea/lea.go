package golea

import (
	"encoding/binary"
	"errors"
)

var delta []uint32 = make([]uint32, 8)
var _ = func() []uint32 {
	delta[0] = 0xc3efe9db
	delta[1] = 0x44626b02
	delta[2] = 0x79e27c8a
	delta[3] = 0x78df30ec
	delta[4] = 0x715ea49e
	delta[5] = 0xc785da0a
	delta[6] = 0xe04ef22a
	delta[7] = 0xe5c40957
	return delta
}()

//LEA block
type LEA struct {
	t  []uint32
	Rk [][]uint32
	Nr int
	Nk int
}

//rol << * x
func rol(src uint32, x int) uint32 {
	return (src << x) | (src >> (32 - x))
}

//ror << * x
func ror(src uint32, x int) uint32 {
	return (src >> x) | (src << (32 - x))
}

func roundEnc(dst, x, rk []uint32) []uint32 {
	dst[0] = rol(
		(x[0]^rk[0])+(x[1]^rk[1]),
		9,
	)
	dst[1] = ror(
		(x[1]^rk[2])+(x[2]^rk[3]),
		5,
	)
	dst[2] = ror(
		(x[2]^rk[4])+(x[3]^rk[5]),
		3,
	)
	dst[3] = x[0]
	return dst
}

//New LEA
func New(key []byte) (LEA, error) {
	keysize := len(key)
	Newcipher := LEA{}
	switch keysize {
	case 128 / 8:
		Newcipher.Nk = 16
		Newcipher.Nr = 24
		Newcipher.t = make([]uint32, 4)
	case 192 / 8:
		Newcipher.Nk = 24
		Newcipher.Nr = 28
		Newcipher.t = make([]uint32, 6)
	case 256 / 8:
		Newcipher.Nk = 32
		Newcipher.Nr = 32
		Newcipher.t = make([]uint32, 8)
	default:
		return Newcipher, errors.New("KeySizeError")
	}

	Newcipher.Rk = make([][]uint32, Newcipher.Nr)
	for i := range Newcipher.Rk {
		Newcipher.Rk[i] = make([]uint32, 6)
	}

	switch Newcipher.Nk {
	case 16:
		Newcipher.t[0] = binary.LittleEndian.Uint32(key[0:4])
		Newcipher.t[1] = binary.LittleEndian.Uint32(key[4:8])
		Newcipher.t[2] = binary.LittleEndian.Uint32(key[8:12])
		Newcipher.t[3] = binary.LittleEndian.Uint32(key[12:16])

		for i := 0; i < 24; i++ {
			Newcipher.t[0] = rol(
				Newcipher.t[0]+rol(
					delta[i%4],
					i,
				),
				1,
			)
			Newcipher.t[1] = rol(
				Newcipher.t[1]+rol(
					delta[i%4],
					i+1,
				),
				3,
			)
			Newcipher.t[2] = rol(
				Newcipher.t[2]+rol(
					delta[i%4],
					i+2,
				),
				6,
			)
			Newcipher.t[3] = rol(
				Newcipher.t[3]+rol(
					delta[i%4],
					i+3,
				),
				11,
			)
			Newcipher.Rk[i][0] = Newcipher.t[0]
			Newcipher.Rk[i][1] = Newcipher.t[1]
			Newcipher.Rk[i][2] = Newcipher.t[2]
			Newcipher.Rk[i][3] = Newcipher.t[1]
			Newcipher.Rk[i][4] = Newcipher.t[3]
			Newcipher.Rk[i][5] = Newcipher.t[1]
		}
	}

	return Newcipher, nil
}

//Encrypt Block
func (Blockcipher LEA) Encrypt(dst, src []byte) {
	X := make([][]uint32, Blockcipher.Nr+1)
	for i := range X {
		X[i] = make([]uint32, 4)
	}
	X[0][0] = binary.LittleEndian.Uint32(src[0:4])
	X[0][1] = binary.LittleEndian.Uint32(src[4:8])
	X[0][2] = binary.LittleEndian.Uint32(src[8:12])
	X[0][3] = binary.LittleEndian.Uint32(src[12:16])
	for i := 0; i < Blockcipher.Nr; i++ {
		roundEnc(X[i+1], X[i], Blockcipher.Rk[i])
	}
	binary.LittleEndian.PutUint32(dst[0:4], X[Blockcipher.Nr][0])
	binary.LittleEndian.PutUint32(dst[4:8], X[Blockcipher.Nr][1])
	binary.LittleEndian.PutUint32(dst[8:12], X[Blockcipher.Nr][2])
	binary.LittleEndian.PutUint32(dst[12:16], X[Blockcipher.Nr][3])
}
