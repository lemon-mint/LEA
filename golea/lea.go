package golea

import (
	"crypto/cipher"
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
	rk [][]uint32
	nr int
	nk int
}

//rol << * x
func rol(src uint32, x int) uint32 {
	return (src << x) | (src >> (32 - x))
}

//ror << * x
func ror(src uint32, x int) uint32 {
	return (src >> x) | (src << (32 - x))
}

func roundEncrypt(dst, x, rk []uint32) []uint32 {
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

func roundDecrypt(dst, x, rk []uint32) []uint32 {
	dst[0] = x[3]
	dst[1] = (ror(x[0], 9) - (dst[0] ^ rk[0])) ^ rk[1]
	dst[2] = (rol(x[1], 5) - (dst[1] ^ rk[2])) ^ rk[3]
	dst[3] = (rol(x[2], 3) - (dst[2] ^ rk[4])) ^ rk[5]
	return dst
}

//New LEA
func New(key []byte) (cipher.Block, error) {
	keysize := len(key)
	Newcipher := LEA{}
	switch keysize {
	case 128 / 8:
		Newcipher.nk = 16
		Newcipher.nr = 24
		Newcipher.t = make([]uint32, 4)
	case 192 / 8:
		Newcipher.nk = 24
		Newcipher.nr = 28
		Newcipher.t = make([]uint32, 6)
	case 256 / 8:
		Newcipher.nk = 32
		Newcipher.nr = 32
		Newcipher.t = make([]uint32, 8)
	default:
		return Newcipher, errors.New("KeySizeError")
	}

	Newcipher.rk = make([][]uint32, Newcipher.nr)
	for i := range Newcipher.rk {
		Newcipher.rk[i] = make([]uint32, 6)
	}

	switch Newcipher.nk {
	case 16:
		Newcipher.t[0] = binary.LittleEndian.Uint32(key[0:4])
		Newcipher.t[1] = binary.LittleEndian.Uint32(key[4:8])
		Newcipher.t[2] = binary.LittleEndian.Uint32(key[8:12])
		Newcipher.t[3] = binary.LittleEndian.Uint32(key[12:16])

		for i := 0; i < Newcipher.nr; i++ {
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
			Newcipher.rk[i][0] = Newcipher.t[0]
			Newcipher.rk[i][1] = Newcipher.t[1]
			Newcipher.rk[i][2] = Newcipher.t[2]
			Newcipher.rk[i][3] = Newcipher.t[1]
			Newcipher.rk[i][4] = Newcipher.t[3]
			Newcipher.rk[i][5] = Newcipher.t[1]
		}

	case 24:
		Newcipher.t[0] = binary.LittleEndian.Uint32(key[0:4])
		Newcipher.t[1] = binary.LittleEndian.Uint32(key[4:8])
		Newcipher.t[2] = binary.LittleEndian.Uint32(key[8:12])
		Newcipher.t[3] = binary.LittleEndian.Uint32(key[12:16])
		Newcipher.t[4] = binary.LittleEndian.Uint32(key[16:20])
		Newcipher.t[5] = binary.LittleEndian.Uint32(key[20:24])

		for i := 0; i < Newcipher.nr; i++ {
			Newcipher.t[0] = rol(
				Newcipher.t[0]+rol(
					delta[i%6],
					i,
				),
				1,
			)
			Newcipher.t[1] = rol(
				Newcipher.t[1]+rol(
					delta[i%6],
					i+1,
				),
				3,
			)
			Newcipher.t[2] = rol(
				Newcipher.t[2]+rol(
					delta[i%6],
					i+2,
				),
				6,
			)
			Newcipher.t[3] = rol(
				Newcipher.t[3]+rol(
					delta[i%6],
					i+3,
				),
				11,
			)
			Newcipher.t[4] = rol(
				Newcipher.t[4]+rol(
					delta[i%6],
					i+4,
				),
				13,
			)
			Newcipher.t[5] = rol(
				Newcipher.t[5]+rol(
					delta[i%6],
					i+5,
				),
				17,
			)
			Newcipher.rk[i][0] = Newcipher.t[0]
			Newcipher.rk[i][1] = Newcipher.t[1]
			Newcipher.rk[i][2] = Newcipher.t[2]
			Newcipher.rk[i][3] = Newcipher.t[3]
			Newcipher.rk[i][4] = Newcipher.t[4]
			Newcipher.rk[i][5] = Newcipher.t[5]
		}
	case 32:
		Newcipher.t[0] = binary.LittleEndian.Uint32(key[0:4])
		Newcipher.t[1] = binary.LittleEndian.Uint32(key[4:8])
		Newcipher.t[2] = binary.LittleEndian.Uint32(key[8:12])
		Newcipher.t[3] = binary.LittleEndian.Uint32(key[12:16])
		Newcipher.t[4] = binary.LittleEndian.Uint32(key[16:20])
		Newcipher.t[5] = binary.LittleEndian.Uint32(key[20:24])
		Newcipher.t[6] = binary.LittleEndian.Uint32(key[24:28])
		Newcipher.t[7] = binary.LittleEndian.Uint32(key[28:32])

		for i := 0; i < Newcipher.nr; i++ {
			Newcipher.t[6*i%8] = rol(
				Newcipher.t[6*i%8]+rol(
					delta[i%8],
					i,
				),
				1,
			)
			Newcipher.t[(6*i+1)%8] = rol(
				Newcipher.t[(6*i+1)%8]+rol(
					delta[i%8],
					(i+1)%32,
				),
				3,
			)
			Newcipher.t[(6*i+2)%8] = rol(
				Newcipher.t[(6*i+2)%8]+rol(
					delta[i%8],
					(i+2)%32,
				),
				6,
			)
			Newcipher.t[(6*i+3)%8] = rol(
				Newcipher.t[(6*i+3)%8]+rol(
					delta[i%8],
					(i+3)%32,
				),
				11,
			)
			Newcipher.t[(6*i+4)%8] = rol(
				Newcipher.t[(6*i+4)%8]+rol(
					delta[i%8],
					(i+4)%32,
				),
				13,
			)
			Newcipher.t[(6*i+5)%8] = rol(
				Newcipher.t[(6*i+5)%8]+rol(
					delta[i%8],
					(i+5)%32,
				),
				17,
			)
			Newcipher.rk[i][0] = Newcipher.t[6*i%8]
			Newcipher.rk[i][1] = Newcipher.t[(6*i+1)%8]
			Newcipher.rk[i][2] = Newcipher.t[(6*i+2)%8]
			Newcipher.rk[i][3] = Newcipher.t[(6*i+3)%8]
			Newcipher.rk[i][4] = Newcipher.t[(6*i+4)%8]
			Newcipher.rk[i][5] = Newcipher.t[(6*i+5)%8]
		}
	}

	for i := range Newcipher.t {
		Newcipher.t[i] = 0
	}
	for i := range Newcipher.t {
		Newcipher.t[i]--
	}

	return Newcipher, nil
}

//Encrypt Block
func (Blockcipher LEA) Encrypt(dst, src []byte) {
	X := make([][]uint32, Blockcipher.nr+1)
	for i := range X {
		X[i] = make([]uint32, 4)
	}
	X[0][0] = binary.LittleEndian.Uint32(src[0:4])
	X[0][1] = binary.LittleEndian.Uint32(src[4:8])
	X[0][2] = binary.LittleEndian.Uint32(src[8:12])
	X[0][3] = binary.LittleEndian.Uint32(src[12:16])
	for i := 0; i < Blockcipher.nr; i++ {
		roundEncrypt(X[i+1], X[i], Blockcipher.rk[i])
	}
	binary.LittleEndian.PutUint32(dst[0:4], X[Blockcipher.nr][0])
	binary.LittleEndian.PutUint32(dst[4:8], X[Blockcipher.nr][1])
	binary.LittleEndian.PutUint32(dst[8:12], X[Blockcipher.nr][2])
	binary.LittleEndian.PutUint32(dst[12:16], X[Blockcipher.nr][3])
}

//Decrypt Block
func (Blockcipher LEA) Decrypt(dst, src []byte) {
	X := make([][]uint32, Blockcipher.nr+1)
	for i := range X {
		X[i] = make([]uint32, 4)
	}
	X[0][0] = binary.LittleEndian.Uint32(src[0:4])
	X[0][1] = binary.LittleEndian.Uint32(src[4:8])
	X[0][2] = binary.LittleEndian.Uint32(src[8:12])
	X[0][3] = binary.LittleEndian.Uint32(src[12:16])
	for i := 0; i < Blockcipher.nr; i++ {
		roundDecrypt(X[i+1], X[i], Blockcipher.rk[Blockcipher.nr-i-1])
	}
	binary.LittleEndian.PutUint32(dst[0:4], X[Blockcipher.nr][0])
	binary.LittleEndian.PutUint32(dst[4:8], X[Blockcipher.nr][1])
	binary.LittleEndian.PutUint32(dst[8:12], X[Blockcipher.nr][2])
	binary.LittleEndian.PutUint32(dst[12:16], X[Blockcipher.nr][3])
}

//BlockSize = 16
func (Blockcipher LEA) BlockSize() int { return 16 }
