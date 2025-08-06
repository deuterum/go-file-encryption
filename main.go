package main

import (
	"flag"
	"log"
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
	key := flag.String("key", "", "")
	enc := flag.Bool("encode", false, "")
	denc := flag.Bool("decode", false, "")
	out := flag.String("out", "", "")

	flag.Parse()

	if enc == denc {
		log.Fatal("Неправильные аргументы")
	}

	if *enc {
		encode(*file, *out, []byte(*key))
	}
	if *denc {
		decode(*file, *out, []byte(*key))
	}
}
