package golea

import (
	"bytes"
	"crypto/cipher"
	"reflect"
	"testing"
)

func Test_roundEnc(t *testing.T) {
	type args struct {
		dst []uint32
		x   []uint32
		rk  []uint32
	}
	tests := []struct {
		name string
		args args
		want []uint32
	}{
		{
			"round0",
			args{
				make([]uint32, 4),
				[]uint32{0x33323130, 0x37363534, 0x3b3a3938, 0x3f3e3d3c},
				[]uint32{0x003a0fd4, 0x02497010, 0x194f7db1, 0x090d0883, 0x2ff5805a, 0xc2580b27},
			},
			[]uint32{0x0f0810d1, 0x030583d2, 0xa246bdef, 0x33323130},
		},
		{
			"round1",
			args{
				make([]uint32, 4),
				[]uint32{0x0f0810d1, 0x030583d2, 0xa246bdef, 0x33323130},
				[]uint32{0xa83e7ef9, 0x053eca29, 0xd359f988, 0x8101a243, 0x9bbf34b3, 0x9228434f},
			},
			[]uint32{0xe370475a, 0x379d1cd0, 0x7b627f7b, 0x0f0810d1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := roundEncrypt(tt.args.dst, tt.args.x, tt.args.rk); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("roundEnc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLEA_Encrypt(t *testing.T) {
	lea128, _ := New([]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0})
	lea192, _ := New([]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87})
	lea256, _ := New([]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f})
	type args struct {
		dst []byte
		src []byte
	}
	tests := []struct {
		name        string
		Blockcipher cipher.Block
		args        args
		want        []byte
	}{
		{
			"128bit",
			lea128,
			args{
				make([]byte, 16),
				[]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
			},
			[]byte{0x9f, 0xc8, 0x4e, 0x35, 0x28, 0xc6, 0xc6, 0x18, 0x55, 0x32, 0xc7, 0xa7, 0x04, 0x64, 0x8b, 0xfd},
		},

		{
			"192bit",
			lea192,
			args{
				make([]byte, 16),
				[]byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
			},
			[]byte{0x6f, 0xb9, 0x5e, 0x32, 0x5a, 0xad, 0x1b, 0x87, 0x8c, 0xdc, 0xf5, 0x35, 0x76, 0x74, 0xc6, 0xf2},
		},

		{
			"256bit",
			lea256,
			args{
				make([]byte, 16),
				[]byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f},
			},
			[]byte{0xd6, 0x51, 0xaf, 0xf6, 0x47, 0xb1, 0x89, 0xc1, 0x3a, 0x89, 0x00, 0xca, 0x27, 0xf9, 0xe1, 0x97},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Blockcipher.Encrypt(tt.args.dst, tt.args.src)
			if !bytes.Equal(tt.args.dst, tt.want) {
				t.Errorf("Blockcipher.Encrypt() = %v, want %v", tt.args.dst, tt.want)
			}
		})
	}
}

func TestLEA_Decrypt(t *testing.T) {
	lea128, _ := New([]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0})
	lea192, _ := New([]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87})
	lea256, _ := New([]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f})

	type args struct {
		dst []byte
		src []byte
	}
	tests := []struct {
		name        string
		Blockcipher cipher.Block
		args        args
		want        []byte
	}{
		{
			"128bit",
			lea128,
			args{
				make([]byte, 16),
				[]byte{0x9f, 0xc8, 0x4e, 0x35, 0x28, 0xc6, 0xc6, 0x18, 0x55, 0x32, 0xc7, 0xa7, 0x04, 0x64, 0x8b, 0xfd},
			},
			[]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
		},

		{
			"192bit",
			lea192,
			args{
				make([]byte, 16),
				[]byte{0x6f, 0xb9, 0x5e, 0x32, 0x5a, 0xad, 0x1b, 0x87, 0x8c, 0xdc, 0xf5, 0x35, 0x76, 0x74, 0xc6, 0xf2},
			},
			[]byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
		},

		{
			"256bit",
			lea256,
			args{
				make([]byte, 16),
				[]byte{0xd6, 0x51, 0xaf, 0xf6, 0x47, 0xb1, 0x89, 0xc1, 0x3a, 0x89, 0x00, 0xca, 0x27, 0xf9, 0xe1, 0x97},
			},
			[]byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Blockcipher.Encrypt(tt.args.dst, tt.args.src)
			if !bytes.Equal(tt.args.dst, tt.want) {
				t.Errorf("Blockcipher.Decrypt() = %v, want %v", tt.args.dst, tt.want)
			}
		})
	}
}

func Test_roundDecrypt(t *testing.T) {
	type args struct {
		dst []uint32
		x   []uint32
		rk  []uint32
	}
	tests := []struct {
		name string
		args args
		want []uint32
	}{
		{
			"round0",
			args{
				make([]uint32, 4),
				[]uint32{0x0f0810d1, 0x030583d2, 0xa246bdef, 0x33323130},
				[]uint32{0x003a0fd4, 0x02497010, 0x194f7db1, 0x090d0883, 0x2ff5805a, 0xc2580b27},
			},
			[]uint32{0x33323130, 0x37363534, 0x3b3a3938, 0x3f3e3d3c},
		},
		{
			"round1",
			args{
				make([]uint32, 4),
				[]uint32{0xe370475a, 0x379d1cd0, 0x7b627f7b, 0x0f0810d1},
				[]uint32{0xa83e7ef9, 0x053eca29, 0xd359f988, 0x8101a243, 0x9bbf34b3, 0x9228434f},
			},
			[]uint32{0x0f0810d1, 0x030583d2, 0xa246bdef, 0x33323130},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := roundDecrypt(tt.args.dst, tt.args.x, tt.args.rk); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("roundDecrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
