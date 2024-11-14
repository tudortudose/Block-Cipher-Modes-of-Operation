package main

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
)

func galoisMultiply(x, y []byte) []byte {
	result := make([]byte, 16)
	v := make([]byte, 16)
	copy(v, x)

	for i := 0; i < 128; i++ {
		if (y[i/8]>>(7-i%8))&1 == 1 {
			for j := range result {
				result[j] ^= v[j]
			}
		}

		isMSBSet := (v[0] & 0x80) != 0
		for j := 0; j < 15; j++ {
			v[j] = (v[j] << 1) | (v[j+1] >> 7)
		}
		v[15] <<= 1

		if isMSBSet {
			v[15] ^= 0x87
		}
	}
	return result
}

func ghash(h, data []byte) []byte {
	y := make([]byte, 16)
	for len(data) > 0 {
		block := data
		if len(data) > 16 {
			block = data[:16]
		}
		for i := 0; i < len(block); i++ {
			y[i] ^= block[i]
		}
		y = galoisMultiply(y, h)
		data = data[len(block):]
	}
	return y
}

func encryptGCM(plaintext, key []byte) (ciphertext, nonce, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	h := make([]byte, aes.BlockSize)
	block.Encrypt(h, h)

	nonce = make([]byte, block.BlockSize()/2)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}

	ciphertext, nonce, err = encryptCTR(plaintext, key)
	if err != nil {
		return nil, nil, nil, err
	}

	authData := []byte{}
	tag = ghash(h, append(authData, ciphertext...))

	return ciphertext, nonce, tag, nil
}

func decryptGCM(ciphertext, key, nonce, expectedTag []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	h := make([]byte, aes.BlockSize)
	block.Encrypt(h, h)

	plaintext, err = decryptCTR(ciphertext, key, nonce)
	if err != nil {
		return nil, err
	}

	authData := []byte{}
	tag := ghash(h, append(authData, ciphertext...))

	if !equal(tag, expectedTag) {
		return nil, errors.New("authentication failed")
	}

	return plaintext, nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
