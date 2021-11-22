package main

import (
	"github.com/raylax/linux-toolkit/module"
	"os"
)

func main() {
	if len(os.Args) == 1 {
		printHelp()
	}
	switch os.Args[1] {
	case "sl":
		module.PrintPortListen()
	default:
		printHelp()
	}
}

func printHelp() {
	println("Use `ltk module`\n  `ltk sl` to print port listen")
	os.Exit(-1)
}
