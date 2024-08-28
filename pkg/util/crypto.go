package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// Key lengths for AES
const (
	AES256KeyLengthBytes = 32
	AES128KeyLengthBytes = 16
)

// SlowBcryptHash hash using Bcrypt
func SlowBcryptHash(data []byte) ([]byte, error) {
	dataHashed, err := bcrypt.GenerateFromPassword(data, 14)
	if err != nil {
		return nil, err
	}
	return dataHashed, nil

}

// SlowBcryptCompareHash CompareHash using Bcrypt BcryptCompareHash
func SlowBcryptCompareHash(hashedData []byte, secret []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedData, secret)
	return err == nil
}

// GenerateKeyForAES256 Generate 32 byte Key For AES 256
func GenerateKeyForAES256(passPhrase string) (*[]byte, error) {
	// 64 bits minimum, 128 bits recommended
	// we use 8*512 = 4096 Bits  to decrease the risk of "repeating the salt"
	salt := *GenerateRandomBytes(512)

	blocksize := 8 // (affects memory and CPU usage)

	// Memory and CPU usage scale linearly with 𝑁
	// we use 32768 2^15
	cpuCost := 1 << 15 // iterations count (affects memory and CPU usage)

	parallelization := 1 // (threads to run in parallel:affects the memory, CPU usage)

	// https://cryptobook.nakov.com/mac-and-key-derivation/scrypt
	// https://blog.filippo.io/the-scrypt-parameters/
	// Memory required = 128 * N * r * p bytes
	derivedKey32Bytes, err := scrypt.Key([]byte(passPhrase), salt, cpuCost, blocksize, parallelization, AES256KeyLengthBytes)
	if err != nil {
		return nil, err
	}
	return &derivedKey32Bytes, nil

}

// AES256GCMEncrypt AES256GCMEncrypt
//
// Example:
// s := []byte("amrit")
// encryptionKey, _ := util.GenerateKeyForAES256("singh")
// d, e := util.AES256GCMEncrypt(&s, encryptionKey)
// encoded := util.Base64STDEncode(*d)
// decoded := util.Base64STDDecode(*encoded)
// dd, ee := util.AES256GCMDecrypt(decoded, encryptionKey)
func AES256GCMEncrypt(plainText *[]byte, encryptionKey *[]byte, nonce *[]byte) (*[]byte, error) {
	// Create `Cipher Block` from the encryption key
	block, err := aes.NewCipher(*encryptionKey)
	if err != nil {
		return nil, err
	}
	// Create GCM
	// https://en.wikipedia.org/wiki/Galois/Counter_Mode
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if nonce == nil {
		nonce = GenerateRandomBytes(aesgcm.NonceSize())
	}
	// Ideally we should save the nonce in the Database
	// So that, when we get the encrypted data back from user (for example)
	// then we use the nonce from DB during decryption phase.
	// `nonce` is the mechanism ensuring the authenticity of data

	// since we are not storing nonce in db,
	// we add nonce as a prefix to the encrypted data.
	// the first nonce argument in Seal is the prefix
	ciphertext := aesgcm.Seal(*nonce, *nonce, *plainText, nil)
	return &ciphertext, err

}

// AES256GCMDecrypt AES256GCMDecrypt
func AES256GCMDecrypt(encryptedText *[]byte, encryptionKey *[]byte) (*[]byte, error) {
	// Create `Cipher Block` from the encryption key
	block, err := aes.NewCipher(*encryptionKey)
	if err != nil {
		return nil, err
	}
	// Create GCM
	// https://en.wikipedia.org/wiki/Galois/Counter_Mode
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	encT := *encryptedText
	nonce := encT[:nonceSize]
	ciphertext := encT[nonceSize:]
	plainText, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return &plainText, nil
}

// SlowScryptCompareHash CompareHash using Scrypt SlowScryptCompareHash
func SlowScryptCompareHash(hashedData []byte, secret []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedData, secret)
	return err == nil
}

// FastYetSecureHash FastYetSecureHash
func FastYetSecureHash(b []byte) ([]byte, error) {
	h := sha512.New()
	_, err := h.Write(b)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// ValidateHash ValidateHash
func ValidateHash(hashFromDB []byte, b []byte) (bool, error) {
	h, err := FastYetSecureHash(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(hashFromDB, h), nil
}
