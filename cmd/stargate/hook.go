package main

import "fmt"
import "os"

func handleHook(args []string, configPath string, verbose bool) int {
	fmt.Fprintln(os.Stderr, "hook: not implemented")
	return 1
}
