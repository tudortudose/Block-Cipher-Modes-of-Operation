package main

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
)

func encryptPCBC(plaintext, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	blockSize := block.BlockSize()
	plaintext = pad(plaintext)

	ciphertext := make([]byte, len(plaintext))
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	prevBlock := iv

	for i := 0; i < len(plaintext); i += blockSize {
		for j := 0; j < blockSize; j++ {
			plaintext[i+j] ^= prevBlock[j]
		}

		block.Encrypt(ciphertext[i:i+blockSize], plaintext[i:i+blockSize])
		prevBlock = ciphertext[i : i+blockSize]
	}

	return ciphertext, iv, nil
}

func decryptPCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(ciphertext) < blockSize {
		return nil, errors.New("ciphertext size must be at least block size")
	}

	plaintext := make([]byte, len(ciphertext))
	prevBlock := iv

	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], ciphertext[i:i+blockSize])

		for j := 0; j < blockSize; j++ {
			plaintext[i+j] ^= prevBlock[j]
		}

		prevBlock = ciphertext[i : i+blockSize]
	}

	return unpad(plaintext)
}
