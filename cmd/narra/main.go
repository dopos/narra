// +build !test

// This file holds code which does not covered by tests

/*
Package main contains only `run(os.Exit)` call.


*/
package main

import (
	"log"
	"os"
)

// Actual version value will be set at build time
var version = "v0.0-dev"

func main() {
	log.Printf("NARRA %s. Nginx Auth Request via Remote Auth server", version)
	run(os.Exit)
}
