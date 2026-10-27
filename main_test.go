package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOversizedInputIsRejected(t *testing.T) {
	if _, err := readLimited(bytes.NewReader(make([]byte, maxPlaintextSize+1)), "input", maxPlaintextSize); err == nil {
		t.Fatal("reading oversized input succeeded")
	}
}

func TestVerifyComparesContents(t *testing.T) {
	a := sealFast(t, testPassword, []byte("same"))
	b, _ := seal(testPassword, []byte("same"), minIterations, bytes.Repeat([]byte{1}, saltSize), bytes.Repeat([]byte{1}, nonceSize))
	c := sealFast(t, testPassword, []byte("different"))
	names := []string{"first", "second"}
	if err := verify(testPassword, names, [][]byte{a, b}); err != nil {
		t.Fatalf("identical contents: %v", err)
	}
	if err := verify(testPassword, names, [][]byte{a, c}); err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("different contents: %v", err)
	}
}

func TestWriteEncryptedRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.donguri")
	if err := writeEncrypted(path, testPassword, []byte("acorn")); err != nil {
		t.Fatal(err)
	}
	file, _ := os.ReadFile(path)
	if got, err := decrypt(testPassword, file); err != nil || string(got) != "acorn" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary file left behind: %v", entries)
	}
}
