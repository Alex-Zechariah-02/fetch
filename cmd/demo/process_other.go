//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// readSecretLine reads one line from the terminal without showing it, with
// no outside program, so it works in the minimal container image too. Input
// that is not a terminal, such as a pipe, is read as it is: nothing shows it.
func readSecretLine(prompt string) (string, error) {
	fmt.Print(prompt)
	defer fmt.Println()
	terminal := int(os.Stdin.Fd())
	if !term.IsTerminal(terminal) {
		return readLine()
	}
	line, err := term.ReadPassword(terminal)
	return string(line), err
}

func newProcessGroup(*exec.Cmd) {}

func interruptProcess(cmd *exec.Cmd) error {
	return cmd.Process.Signal(os.Interrupt)
}

func lockEarlierDemoFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func privateDirectory(path string) error {
	return os.Mkdir(path, 0o700)
}
