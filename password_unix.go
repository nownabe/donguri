//go:build linux || darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

func openTerminal() (in, out *os.File, err error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	return tty, tty, err
}

func disableEcho(tty *os.File) (restore func(), err error) {
	fd := tty.Fd()
	var original syscall.Termios
	if err := ioctlTermios(fd, ioctlGetTermios, &original); err != nil {
		return nil, err
	}
	noEcho := original
	noEcho.Lflag &^= syscall.ECHO
	if err := ioctlTermios(fd, ioctlSetTermios, &noEcho); err != nil {
		return nil, err
	}
	return func() { ioctlTermios(fd, ioctlSetTermios, &original) }, nil
}

func ioctlTermios(fd, request uintptr, t *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(unsafe.Pointer(t))); errno != 0 {
		return errno
	}
	return nil
}
