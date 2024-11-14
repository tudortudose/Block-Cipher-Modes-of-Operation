package main

import (
	"bytes"
	"crypto/aes"
	"errors"
)

func pad(plaintext []byte) []byte {
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

func unpad(plaintext []byte) ([]byte, error) {
	length := len(plaintext)
	if length == 0 {
		return nil, errors.New("input length is zero")
	}

	padding := plaintext[length-1]
	if int(padding) > length {
		return nil, errors.New("padding size is invalid")
	}
	return plaintext[:length-int(padding)], nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func xorBytes(dst, a, b []byte) {
	for i := range a {
		dst[i] = a[i] ^ b[i]
	}
}
