package util

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mathRand "math/rand"
	"unsafe"

	"github.com/segmentio/ksuid"
)

var (
	srcForMathRand   mathRand.Source
	tableOfStringInt = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// assertAvailablePRNG ...

// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should NOT continue.

// -----------------------------
// We can use the following code also
// ------------------------------

// var b [8]byte
// _, err := cryptoRand.Read(b[:])
// if err != nil {
// 	panic("cannot seed math/rand package with CSPRNG")
// }
func assertAvailablePRNG(n uint) {
	// Assert that a CSPRNG is available.
	buf := make([]byte, n)                        //slice now contains all zeroes
	_, err := io.ReadFull(cryptoRand.Reader, buf) //slice now contains all zeroes
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
	// The slice should now contain random bytes instead of only zeroes.
	// Output:
	// false
}

// GenerateRandomBytes returns securely generated random bytes.
//
// This is a CSPRNG
func GenerateRandomBytes(n int) *[]byte {
	b := make([]byte, n)
	// https://golang.org/src/crypto/rand/example_test.go
	// It uses cryptoRand.Reader, which we tested in assertAvailablePRNG
	// during package init.
	// So, the error part is already handled in assertAvailablePRNG()
	cryptoRand.Read(b)
	return &b
}

// GenerateRandomStringURLSafe returns a URL-safe, base64 encoded
// securely generated random string.
func GenerateRandomStringURLSafe(n int) string {
	// hex.EncodeToString
	return Base64URLEncode(*GenerateRandomBytes(n))
}

// GenerateRandomInteger GenerateRandomInteger of fixed length
func GenerateRandomInteger(numDigits int) []byte {
	b := *GenerateRandomBytes(numDigits)
	for i := 0; i < len(b); i++ {
		b[i] = tableOfStringInt[int(b[i])%len(tableOfStringInt)]
	}
	return b
	// i, _ := cryptoRand.Int(rand.Reader, big.NewInt(999999))
	// return i
}

// GenerateUUID ...
func GenerateUUID() string {
	return ksuid.New().String()
}

// InspectKSUID InspectKSUID
func InspectKSUID(s string) (ksuid.KSUID, error) {
	return ksuid.Parse(s)
}

// GenerateShortID ...
// For generating a password or a cryptographic key, etc, never use math/rand; use crypto/rand
func GenerateShortID(n int) string {
	mathbuf := make([]byte, 10240)
	io.ReadFull(cryptoRand.Reader, mathbuf) // the error part is already handled in assertAvailablePRNG
	srcForMathRand = mathRand.NewSource(int64(binary.LittleEndian.Uint64(mathbuf[:])))
	b := make([]byte, n)
	for i, cache, remain := n-1, srcForMathRand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = srcForMathRand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return *(*string)(unsafe.Pointer(&b))
}
