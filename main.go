package main

import (
	"context"
	"fmt"
	"os"

	"goftp/internal/cli"
)

func main() {
	if err := cli.Execute(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "goftp:", err)
		os.Exit(1)
	}
}
