package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

const (
	magic             = "DONGURI\x00"
	formatV1          = 0x01
	kdfPBKDF2SHA256   = 0x01
	saltSize          = 16
	nonceSize         = 12
	tagSize           = 16
	keySize           = 32
	headerSize        = len(magic) + 1 + 1 + 4 + saltSize + nonceSize
	defaultIterations = 600_000
	minIterations     = 100_000
	maxIterations     = 10_000_000
	maxPlaintextSize  = 16 << 20
	maxFileSize       = headerSize + maxPlaintextSize + tagSize
)

var errAuth = errors.New("wrong password or corrupted file")

func encrypt(password, plaintext []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	nonce := make([]byte, nonceSize)
	rand.Read(salt)
	rand.Read(nonce)
	return seal(password, plaintext, defaultIterations, salt, nonce)
}

func seal(password, plaintext []byte, iterations uint32, salt, nonce []byte) ([]byte, error) {
	if len(plaintext) > maxPlaintextSize {
		return nil, fmt.Errorf("input is larger than the maximum of %d bytes", maxPlaintextSize)
	}
	if err := checkIterations(iterations); err != nil {
		return nil, err
	}

	header := make([]byte, 0, headerSize)
	header = append(header, magic...)
	header = append(header, formatV1, kdfPBKDF2SHA256)
	header = binary.BigEndian.AppendUint32(header, iterations)
	header = append(header, salt...)
	header = append(header, nonce...)

	aead, err := newAEAD(password, salt, iterations)
	if err != nil {
		return nil, err
	}
	return aead.Seal(header, nonce, plaintext, header), nil
}

func decrypt(password, file []byte) ([]byte, error) {
	if len(file) < len(magic) || string(file[:len(magic)]) != magic {
		return nil, errors.New("not a donguri file")
	}
	if len(file) < headerSize+tagSize {
		return nil, errors.New("file is truncated")
	}
	if len(file) > maxFileSize {
		return nil, fmt.Errorf("file is larger than the maximum of %d bytes", maxFileSize)
	}
	if v := file[8]; v != formatV1 {
		return nil, fmt.Errorf("unsupported format version %d", v)
	}
	if k := file[9]; k != kdfPBKDF2SHA256 {
		return nil, fmt.Errorf("unknown KDF identifier %d", k)
	}
	iterations := binary.BigEndian.Uint32(file[10:14])
	if err := checkIterations(iterations); err != nil {
		return nil, err
	}
	salt := file[14 : 14+saltSize]
	nonce := file[14+saltSize : headerSize]

	aead, err := newAEAD(password, salt, iterations)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, file[headerSize:], file[:headerSize])
	if err != nil {
		return nil, errAuth
	}
	return plaintext, nil
}

func checkIterations(n uint32) error {
	if n < minIterations || n > maxIterations {
		return fmt.Errorf("iteration count %d is outside the allowed range %d to %d", n, minIterations, maxIterations)
	}
	return nil
}

func newAEAD(password, salt []byte, iterations uint32) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, aliasString(password), salt, int(iterations), keySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// pbkdf2.Key takes a string; converting normally would leave a copy of the password that cannot be wiped.
func aliasString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}
