package main

import (
	"fmt"
	"log"
	"net"

	"github.com/grandcat/zeroconf"
)

func getIP() string {
	conn, err := net.Dial("udp", "10.255.255.255:1")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func main() {
	// Register GoPeer._ping._tcp.local.
	server, err := zeroconf.Register(
		"GoPeer",     // Name
		"_ping._tcp", // Service type
		"local.",     // Domain
		12346,        // Port
		[]string{},   // No TXT records
		nil,          // Use system IP
	)
	// If an error is logged
	// GO error logging is silly
	if err != nil {
		log.Fatal(err)
	}
	defer server.Shutdown()

	// You can create and immediately call a function in GO
	// UDP Listener on port 12345
	go func() {
		// Find the address
		addr := net.UDPAddr{
			Port: 12346,
			IP:   net.ParseIP("0.0.0.0"),
		}

		// Pass in the address and create a connection
		connection, err := net.ListenUDP("udp", &addr)
		if err != nil {
			log.Fatal(err)
		}
		defer connection.Close()

		buffer := make([]byte, 1024)
		for {
			n, remoteAddr, err := connection.ReadFromUDP(buffer)
			if err != nil {
				log.Println("Error reading:", err)
				continue
			}
			fmt.Printf("Recieved from %s: %s\n", remoteAddr, string(buffer[:n]))
		}
	}()

	log.Println("Service registered as GoPeer._ping._tcp.local on port 12345")

	fmt.Println("Local IP Address:", getIP())

	// Keep the program alive (like a while True)
	select {}
}
