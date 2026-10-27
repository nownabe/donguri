package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Set at release build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "unknown"
)

const usage = `Usage:
  donguri encrypt -o <out> [--force] [<in>]
  donguri decrypt <file>
  donguri verify <file> [<file2>]
  donguri --version
`

var errUsage = errors.New("invalid usage")

func main() {
	err := run(os.Args[1:])
	switch {
	case err == nil:
	case errors.Is(err, errUsage):
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "donguri:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "encrypt":
		return runEncrypt(rest)
	case "decrypt":
		return runDecrypt(rest)
	case "verify":
		return runVerify(rest)
	case "--version", "-version":
		fmt.Printf("donguri %s (commit %s)\n", version, commit)
		return nil
	default:
		return errUsage
	}
}

func runEncrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("o", "", "output file")
	force := fs.Bool("force", false, "overwrite the output file if it exists")
	if err := fs.Parse(args); err != nil || *out == "" || fs.NArg() > 1 {
		return errUsage
	}

	if !*force {
		if _, err := os.Lstat(*out); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", *out)
		}
	}

	var plaintext []byte
	var err error
	if fs.NArg() == 1 {
		plaintext, err = readFile(fs.Arg(0), maxPlaintextSize)
	} else {
		plaintext, err = readLimited(os.Stdin, "standard input", maxPlaintextSize)
	}
	if err != nil {
		return err
	}
	password, err := readNewPassword()
	if err != nil {
		return err
	}
	defer clear(password)

	if err := writeEncrypted(*out, password, plaintext); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Encrypted and verified %s\n", *out)
	return nil
}

func readNewPassword() ([]byte, error) {
	password, err := readPassword("Password: ")
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	confirmation, err := readPassword("Confirm password: ")
	defer clear(confirmation)
	if err != nil || !bytes.Equal(password, confirmation) {
		clear(password)
		if err == nil {
			err = errors.New("passwords do not match")
		}
		return nil, err
	}
	return password, nil
}

func writeEncrypted(path string, password, plaintext []byte) error {
	file, err := encrypt(password, plaintext)
	if err != nil {
		return err
	}
	return writeAtomically(path, file, func(written string) error {
		if err := verifyWritten(written, password, plaintext); err != nil {
			return fmt.Errorf("read-back check failed, %s left unchanged: %w", path, err)
		}
		return nil
	})
}

func writeAtomically(path string, data []byte, checkBeforeRename func(tmpPath string) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".donguri-*.tmp")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := checkBeforeRename(tmp.Name()); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	committed = true
	return nil
}

func verifyWritten(path string, password, plaintext []byte) error {
	written, err := readFile(path, maxFileSize)
	if err != nil {
		return err
	}
	decrypted, err := decrypt(password, written)
	if err != nil {
		return err
	}
	if !bytes.Equal(decrypted, plaintext) {
		return errors.New("decrypted contents differ from the input")
	}
	return nil
}

func runDecrypt(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	file, err := readFile(args[0], maxFileSize)
	if err != nil {
		return err
	}
	password, err := readPassword("Password: ")
	if err != nil {
		return err
	}
	plaintext, err := decrypt(password, file)
	clear(password)
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	_, err = os.Stdout.Write(plaintext)
	return err
}

func runVerify(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errUsage
	}
	files := make([][]byte, len(args))
	for i, path := range args {
		var err error
		if files[i], err = readFile(path, maxFileSize); err != nil {
			return err
		}
	}
	password, err := readPassword("Password: ")
	if err != nil {
		return err
	}
	defer clear(password)
	if err := verify(password, args, files); err != nil {
		return err
	}
	fmt.Println("OK")
	return nil
}

func verify(password []byte, names []string, files [][]byte) error {
	plaintexts := make([][]byte, len(files))
	for i, file := range files {
		var err error
		if plaintexts[i], err = decrypt(password, file); err != nil {
			return fmt.Errorf("%s: %w", names[i], err)
		}
	}
	if len(plaintexts) == 2 && !bytes.Equal(plaintexts[0], plaintexts[1]) {
		return fmt.Errorf("%s and %s decrypt to different contents", names[0], names[1])
	}
	return nil
}

func readFile(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimited(f, path, limit)
}

func readLimited(r io.Reader, name string, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s is larger than the maximum of %d bytes", name, limit)
	}
	return data, nil
}
