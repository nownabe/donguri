package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

var testPassword = []byte("correct horse battery staple")

func sealFast(t *testing.T, password, plaintext []byte) []byte {
	t.Helper()
	file, err := seal(password, plaintext, minIterations, make([]byte, saltSize), make([]byte, nonceSize))
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestRoundTrip(t *testing.T) {
	for name, plaintext := range map[string][]byte{
		"empty":    {},
		"one byte": {0x42},
		"maximum":  bytes.Repeat([]byte{0xA5}, maxPlaintextSize),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decrypt(testPassword, sealFast(t, testPassword, plaintext))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("plaintext mismatch")
			}
		})
	}
}

func TestEncryptUsesDefaultIterationsAndFreshRandomness(t *testing.T) {
	a, err := encrypt(testPassword, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := encrypt(testPassword, []byte("x"))
	if bytes.Equal(a[14:headerSize], b[14:headerSize]) {
		t.Fatal("salt and nonce were reused")
	}
	if got, err := decrypt(testPassword, a); err != nil || string(got) != "x" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
}

func TestOversizedPlaintextIsRejected(t *testing.T) {
	if _, err := seal(testPassword, make([]byte, maxPlaintextSize+1), minIterations, make([]byte, saltSize), make([]byte, nonceSize)); err == nil {
		t.Fatal("encrypting oversized input succeeded")
	}
}

func TestOutOfRangeIterationCountIsRejected(t *testing.T) {
	for _, n := range []uint32{minIterations - 1, maxIterations + 1} {
		if _, err := seal(testPassword, nil, n, make([]byte, saltSize), make([]byte, nonceSize)); err == nil {
			t.Errorf("encrypting with %d iterations succeeded", n)
		}
		file := sealFast(t, testPassword, nil)
		binary.BigEndian.PutUint32(file[10:14], n)
		if _, err := decrypt(testPassword, file); err == nil || errors.Is(err, errAuth) {
			t.Errorf("decrypting with %d iterations = %v, want iteration count error", n, err)
		}
	}
}

func TestEverySingleByteChangeFails(t *testing.T) {
	original := sealFast(t, testPassword, []byte("secret"))
	for i := range original {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			file := bytes.Clone(original)
			file[i] ^= 0x01
			if _, err := decrypt(testPassword, file); err == nil {
				t.Fatalf("decryption succeeded after changing byte %d", i)
			}
		})
	}
}

func TestWrongPasswordFails(t *testing.T) {
	file := sealFast(t, testPassword, []byte("secret"))
	if _, err := decrypt([]byte("wrong"), file); !errors.Is(err, errAuth) {
		t.Fatalf("decrypt = %v, want %v", err, errAuth)
	}
}

func TestVectorInFormatDocument(t *testing.T) {
	doc, err := os.ReadFile("FORMAT.md")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("Buried in autumn, dug up in spring.\n")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	nonce, _ := hex.DecodeString("101112131415161718191a1b")
	got, err := seal(testPassword, plaintext, 600_000, salt, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(doc, []byte(hex.EncodeToString(got))) {
		t.Fatalf("FORMAT.md does not contain the encrypted file %x", got)
	}
}
