package util

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"io"
	mathRand "math/rand"

	"github.com/segmentio/ksuid"
)

func init() {
	assertAvailablePRNG(10240)

	crypbuf := make([]byte, 10240)
	io.ReadFull(cryptoRand.Reader, crypbuf)
	mathRand.Seed(int64(binary.LittleEndian.Uint64(crypbuf[:]))) // for non-deterministic generation

	ksuid.SetRand(cryptoRand.Reader)
}
