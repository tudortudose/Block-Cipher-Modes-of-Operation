package main

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"io"
)

func encryptCBC(plaintext, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	blockSize := block.BlockSize()

	plaintext = pad(plaintext)

	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	ciphertext := make([]byte, len(plaintext))

	prevCiphertext := iv

	for i := 0; i < len(plaintext); i += blockSize {
		xorBlock := make([]byte, blockSize)
		xorBytes(xorBlock, plaintext[i:i+blockSize], prevCiphertext)

		block.Encrypt(ciphertext[i:i+blockSize], xorBlock)

		prevCiphertext = ciphertext[i : i+blockSize]
	}

	return ciphertext, iv, nil
}

func decryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))

	prevCiphertext := iv

	for i := 0; i < len(ciphertext); i += blockSize {
		decryptedBlock := make([]byte, blockSize)
		block.Decrypt(decryptedBlock, ciphertext[i:i+blockSize])

		xorBytes(plaintext[i:i+blockSize], decryptedBlock, prevCiphertext)

		prevCiphertext = ciphertext[i : i+blockSize]
	}

	return unpad(plaintext)
}
