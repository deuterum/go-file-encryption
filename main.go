package main

import (
	"flag"
	"log"
	"os"
)

const (
	blockSize  = 1 << 20 // 1 MB
	numWorkers = 8       // Количество потоков
)

type block struct {
	index int
	data  []byte
}

func main() {
	file := flag.String("in", "", "")
	keyStr := flag.String("key", "", "")
	enc := flag.Bool("encode", false, "")
	denc := flag.Bool("decode", false, "")
	out := flag.String("out", "", "")
	hash := flag.Bool("hash", false, "")

	flag.Parse()

	if *enc == *denc {
		log.Fatal("Неправильные аргументы")
	}
	if *keyStr == "" {
		log.Fatal("Отсутствует ключ: -key examplekey")
	}

	dir, _ := os.Getwd()
	if *hash && *enc {
		log.Println("Создание хеш файла...")
		makeHashFile(*file, *out+".hash", dir)
	}

	key := to16Bytes(*keyStr)

	if *enc {
		encode(*file, *out, key)
	}
	if *denc {
		decode(*file, *out, key)
		checkHashFile(*out, *file+".hash", dir, dir)
	}
}
