package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

func encryptCTR(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	blockSize := block.BlockSize()

	nonce = make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = make([]byte, len(plaintext))
	keystream := make([]byte, blockSize)

	for i := 0; i < len(plaintext); i += blockSize {
		counterBlock := make([]byte, blockSize)
		copy(counterBlock, nonce)
		binary.BigEndian.PutUint32(counterBlock[blockSize-4:], uint32(i/blockSize))

		block.Encrypt(keystream, counterBlock)

		blockSizeRemaining := min(blockSize, len(plaintext)-i)
		for j := 0; j < blockSizeRemaining; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ keystream[j]
		}
	}

	return ciphertext, nonce, nil
}

func decryptCTR(ciphertext, key, nonce []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(nonce) != blockSize {
		return nil, errors.New("invalid nonce size")
	}

	plaintext = make([]byte, len(ciphertext))
	keystream := make([]byte, blockSize)

	for i := 0; i < len(ciphertext); i += blockSize {
		counterBlock := make([]byte, blockSize)
		copy(counterBlock, nonce)
		binary.BigEndian.PutUint32(counterBlock[blockSize-4:], uint32(i/blockSize))

		block.Encrypt(keystream, counterBlock)

		blockSizeRemaining := min(blockSize, len(ciphertext)-i)
		for j := 0; j < blockSizeRemaining; j++ {
			plaintext[i+j] = ciphertext[i+j] ^ keystream[j]
		}
	}

	return plaintext, nil
}
