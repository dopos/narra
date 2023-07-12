//go:build !test
// +build !test

// This file holds code which does not covered by tests

package main

import "os"

var (
	// App version, actual value will be set at build time
	version = "0.0-dev"

	// Repository address, actual value will be set at build time
	repo = "repo.git"
)

func main() {
	Run(version, os.Exit)
}
