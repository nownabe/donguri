package main

import (
	"os"
	"syscall"
)

const enableEchoInput = 0x0004

var setConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")

func openTerminal() (in, out *os.File, err error) {
	in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	out, err = os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		in.Close()
		return nil, nil, err
	}
	return in, out, nil
}

func disableEcho(console *os.File) (restore func(), err error) {
	h := syscall.Handle(console.Fd())
	var original uint32
	if err := syscall.GetConsoleMode(h, &original); err != nil {
		return nil, err
	}
	if err := setMode(h, original&^enableEchoInput); err != nil {
		return nil, err
	}
	return func() { setMode(h, original) }, nil
}

func setMode(h syscall.Handle, mode uint32) error {
	if r, _, err := setConsoleMode.Call(uintptr(h), uintptr(mode)); r == 0 {
		return err
	}
	return nil
}
