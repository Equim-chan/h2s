package h2s

import (
	"io"
	"sync"
)

var (
	pipeBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 128*1024)
		},
	}
)

func duplexPipe(x, y io.ReadWriteCloser) {
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		buf := pipeBufPool.Get().([]byte)
		io.CopyBuffer(x, y, buf)
		pipeBufPool.Put(buf)
		x.Close()
		wg.Done()
	}()

	go func() {
		buf := pipeBufPool.Get().([]byte)
		io.CopyBuffer(y, x, buf)
		pipeBufPool.Put(buf)
		y.Close()
		wg.Done()
	}()

	wg.Wait()
}
