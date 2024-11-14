package main

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
)

func encryptOFB(plaintext, key []byte) (ciphertext, iv []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	blockSize := block.BlockSize()
	iv = make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	ciphertext = make([]byte, len(plaintext))
	keystream := make([]byte, blockSize)

	copy(keystream, iv)

	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(keystream, keystream)

		blockSizeRemaining := min(blockSize, len(plaintext)-i)
		for j := 0; j < blockSizeRemaining; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ keystream[j]
		}
	}

	return ciphertext, iv, nil
}

func decryptOFB(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("invalid IV size")
	}

	plaintext := make([]byte, len(ciphertext))
	keystream := make([]byte, blockSize)

	copy(keystream, iv)

	for i := 0; i < len(ciphertext); i += blockSize {
		block.Encrypt(keystream, keystream)

		blockSizeRemaining := min(blockSize, len(ciphertext)-i)
		for j := 0; j < blockSizeRemaining; j++ {
			plaintext[i+j] = ciphertext[i+j] ^ keystream[j]
		}
	}

	return plaintext, nil
}
