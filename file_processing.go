package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

func encode(inputPath, outputPath string, key []byte) {
	inFile, err := os.Open(inputPath)
	if err != nil {
		log.Fatal("Ошибка открытия входного файла:", err)
	}
	defer inFile.Close()
	info, _ := inFile.Stat()

	outFile, err := os.Create(outputPath)
	if err != nil {
		log.Fatal("Ошибка создания выходного файла:", err)
	}
	defer outFile.Close()

	// Генерируем IV (инициализационный вектор)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		log.Fatal("Ошибка генерации IV:", err)
	}
	_, _ = outFile.Write(iv) // Сохраняем IV в начало файла

	// Каналы
	inputChan := make(chan block, numWorkers)
	outputChan := make(chan block, numWorkers)

	var wg sync.WaitGroup

	// Запуск воркеров
	log.Printf("Начато шифрование файла - %s, Размер - %d\n", info.Name(), info.Size())
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go workerEncrypt(key, iv, inputChan, outputChan, &wg)
	}
	log.Printf("Запущено потоков - %d", numWorkers)

	// Чтение и отправка блоков на шифрование
	go func() {
		index := 0
		for {
			Bar(index, int(info.Size())/blockSize)
			buf := make([]byte, blockSize)
			n, err := inFile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal("Ошибка чтения файла:", err)
			}
			if n == 0 {
				break
			}
			inputChan <- block{index: index, data: buf[:n]}
			index++
		}
		close(inputChan)
	}()

	// Запись зашифрованных блоков в правильном порядке
	go func() {
		wg.Wait()
		close(outputChan)
	}()

	// Сохраняем результат
	writeBlocksInOrder(outputChan, outFile)
	fmt.Print("\n")
	log.Printf("Файл зашифрован в %s", outputPath)
}

func decode(inputPath, outputPath string, key []byte) {
	inFile, err := os.Open(inputPath)
	if err != nil {
		log.Fatal("Ошибка открытия входного файла:", err)
	}
	defer inFile.Close()
	info, _ := inFile.Stat()

	outFile, err := os.Create(outputPath)
	if err != nil {
		log.Fatal("Ошибка создания выходного файла:", err)
	}
	defer outFile.Close()

	// Читаем IV (первые 16 байт)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(inFile, iv); err != nil {
		log.Fatal("Ошибка чтения IV:", err)
	}

	// Каналы
	inputChan := make(chan block, numWorkers)
	outputChan := make(chan block, numWorkers)

	var wg sync.WaitGroup

	// Запускаем дешифрующие воркеры
	log.Printf("Начато дешифрование файла - %s, Размер - %d\n", info.Name(), info.Size())
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go workerDecrypt(key, iv, inputChan, outputChan, &wg)
	}
	log.Printf("Запущено потоков - %d", numWorkers)

	// Чтение и передача блоков на дешифровку

	go func() {
		index := 0
		for {
			Bar(index, int(info.Size())/blockSize)
			buf := make([]byte, blockSize)
			n, err := inFile.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal("Ошибка чтения зашифрованного файла:", err)
			}
			if n == 0 {
				break
			}
			inputChan <- block{index: index, data: buf[:n]}
			index++
		}
		close(inputChan)
	}()

	// Закрытие выходного канала после завершения всех горутин
	go func() {
		wg.Wait()
		close(outputChan)
	}()

	// Запись расшифрованных блоков в файл
	writeBlocksInOrder(outputChan, outFile)
	fmt.Print("\n")
	log.Printf("Файл разшифрован в %s", outputPath)
}

// Увеличивает IV на index
func incrementIV(iv []byte, index int) {
	n := len(iv)
	for i := n - 1; i >= 0 && index > 0; i-- {
		sum := int(iv[i]) + (index & 0xff)
		iv[i] = byte(sum & 0xff)
		index >>= 8
	}
}

// Пишет блоки в файл по порядку
func writeBlocksInOrder(outputChan <-chan block, outFile *os.File) {
	blockMap := make(map[int][]byte)
	expected := 0

	for blk := range outputChan {
		blockMap[blk.index] = blk.data

		// Записываем блоки по порядку, если они готовы
		for {
			if data, ok := blockMap[expected]; ok {
				_, err := outFile.Write(data)
				if err != nil {
					log.Fatal("Ошибка записи в файл:", err)
				}
				delete(blockMap, expected)
				expected++
			} else {
				break
			}
		}
	}
}

func to16Bytes(s string) []byte {
	b := []byte(s)

	if len(b) > 16 {
		return b[:16]
	}

	if len(b) < 16 {
		padded := make([]byte, 16)
		copy(padded, b)
		return padded
	}

	return b
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

func checkHashFile(filename, hash_filename, hash_folder, file_folder string) {
	log.Println("Проверка хеша...")
	if !fileExists(filepath.Join(hash_folder, hash_filename)) {
		log.Println("Хеш файла не найден")
		return
	}

	hashBefore, err := os.ReadFile(filepath.Join(hash_folder, hash_filename))
	if err != nil {
		panic(err)
	}

	file, err := os.Open(filepath.Join(file_folder, filename))
	if err != nil {
		panic(err)
	}
	defer file.Close()

	hasher := sha256.New()
	_, err = io.Copy(hasher, file)
	if err != nil {
		panic(err)
	}
	hashAfter := hasher.Sum(nil)

	equal := bytes.Equal(hashBefore, hashAfter)

	if equal {
		log.Println("Хеш проверка пройдена")
	} else {
		log.Println("Хеш проверка провалена")
	}
}

func makeHashFile(filename, hash_filename, folder string) {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	hasher := sha256.New()
	_, err = io.Copy(hasher, file)
	if err != nil {
		panic(err)
	}

	hash_sum := hasher.Sum(nil)
	hash_file, err := os.Create(filepath.Join(folder, hash_filename))
	if err != nil {
		panic(err)
	}
	defer hash_file.Close()

	_, err = hash_file.Write(hash_sum)
	if err != nil {
		panic(err)
	}
}
