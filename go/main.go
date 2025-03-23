package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

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

	// Discovery
	go func() {
		resolver, err := zeroconf.NewResolver(nil)
		if err != nil {
			log.Fatalln("Failed to initialize resolver:", err)
		}

		// Tracks all of the entries
		entries := make(chan *zeroconf.ServiceEntry)
		// Wait 10 seconds
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Print out the results
		// Inline function
		// It's like javascript!
		go func(results <-chan *zeroconf.ServiceEntry) {
			for entry := range results {
				fmt.Printf("Discovered: %s\n", entry.Instance)
				for _, ip := range entry.AddrIPv4 {
					fmt.Printf("  IP: %s, Port: %d\n", ip, entry.Port)
				}
			}
		}(entries)

		log.Println("Looking for services of type _ping._tcp.local...")
		err = resolver.Browse(ctx, "_ping._tcp", "local.", entries)
		if err != nil {
			log.Fatalln("Browse failed:", err)
		}

		// Determines when discovery is finished
		<-ctx.Done()
		log.Println("Discovery complete.")
	}()

	log.Println("Service registered as GoPeer._ping._tcp.local on port 12345")

	fmt.Println("Local IP Address:", getIP())

	// Keep the program alive (like a while True)
	select {}
}
