package main

import (
	"log"

	"github.com/grandcat/zeroconf"
)

func main() {
	// Register GoPeer._ping._tcp.local.
	server, err := zeroconf.Register(
		"GoPeer",     // Name
		"_ping._tcp", // Service type
		"local.",     // Domain
		12345,        // Port
		[]string{},   // No TXT records
		nil,          // Use system IP
	)
	// If an error is logged
	// GO error logging is silly
	if err != nil {
		log.Fatal(err)
	}
	defer server.Shutdown()

	log.Println("Service registered as GoPeer._ping._tcp.local on port 12345")

	// Keep the program alive (like a while True)
	select {}
}
