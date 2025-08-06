package main

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"sync"
)

func workerDecrypt(key, iv []byte, inputChan <-chan block, outputChan chan<- block, wg *sync.WaitGroup) {
	defer wg.Done()
	for blk := range inputChan {
		blockCipher, err := aes.NewCipher(key)
		if err != nil {
			log.Fatal("Ошибка создания AES:", err)
		}

		ctrIV := make([]byte, aes.BlockSize)
		copy(ctrIV, iv)
		incrementIV(ctrIV, blk.index)

		stream := cipher.NewCTR(blockCipher, ctrIV)
		dst := make([]byte, len(blk.data))
		stream.XORKeyStream(dst, blk.data)

		outputChan <- block{index: blk.index, data: dst}
	}
}
