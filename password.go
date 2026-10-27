package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
)

func readPassword(prompt string) ([]byte, error) {
	in, out, err := openTerminal()
	if err != nil {
		return nil, fmt.Errorf("a terminal is required to read the password: %w", err)
	}
	defer in.Close()
	defer out.Close()

	restore, err := disableEcho(in)
	if err != nil {
		return nil, fmt.Errorf("cannot disable terminal echo: %w", err)
	}
	defer restore()
	stop := restoreOnInterrupt(restore)
	defer stop()

	fmt.Fprint(out, prompt)
	password, err := readLine(in)
	fmt.Fprintln(out)
	return password, err
}

// Without this, Ctrl-C at the prompt would leave the user's terminal with echo turned off.
func restoreOnInterrupt(restore func()) (stop func()) {
	interrupted := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(interrupted, os.Interrupt)
	go func() {
		select {
		case <-interrupted:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(interrupted)
		close(done)
	}
}

// Reads byte by byte instead of through bufio so that no copy of the password is left in a buffer we cannot wipe.
func readLine(r io.Reader) ([]byte, error) {
	line := make([]byte, 0, 128)
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			line = appendWiping(line, b[0])
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			clear(line)
			return nil, err
		}
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line[n-1] = 0
		line = line[:n-1]
	}
	return line, nil
}

func appendWiping(s []byte, c byte) []byte {
	if len(s) < cap(s) {
		return append(s, c)
	}
	grown := make([]byte, len(s), 2*cap(s))
	copy(grown, s)
	clear(s)
	return append(grown, c)
}
