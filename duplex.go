package h2s

import (
	"io"
	"sync"
)

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

var pipeBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 128*1024)
	},
}

func duplexPipe(x, y io.ReadWriter) {
	var wg sync.WaitGroup
	wg.Add(2)

	go pipe(x, y, &wg)
	go pipe(y, x, &wg)

	wg.Wait()
}

func pipe(x, y io.ReadWriter, wg *sync.WaitGroup) {
	buf := pipeBufPool.Get().([]byte)
	io.CopyBuffer(x, y, buf)
	pipeBufPool.Put(buf)

	if cw, ok := x.(closeWriter); ok {
		cw.CloseWrite()
	}
	if cr, ok := y.(closeReader); ok {
		cr.CloseRead()
	}

	wg.Done()
}
