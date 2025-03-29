package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/grandcat/zeroconf"
)

func discoverServices() {
	// Create a new Zeroconf service resolver
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatal("Failed to create resolver: ", err)
	}

	// Discover all _ping._tcp. peers
	serviceType := "_ping._tcp."

	// Create a context to pass to the resolver
	ctx := context.Background()

	// Start the service resolution in the background
	entries := make(chan *zeroconf.ServiceEntry)

	go func() {
		// Discover services of type "_ping._tcp" on my computer
		if err := resolver.Browse(ctx, serviceType, "", entries); err != nil {
			log.Fatal("Error starting service browse: ", err)
		}

		// Listen for discovered services and print their details
		for entry := range entries {
			fmt.Printf("Discovered service: %s\n", entry.Service)
			fmt.Printf("Host: %s\n", entry.HostName)
			fmt.Printf("Address: %s\n", entry.AddrIPv4)
			fmt.Printf("Port: %d\n", entry.Port)
			fmt.Printf("Text: %v\n\n", entry.Text)
		}
	}()
}

func main() {
	// Re-run the searcher every 10 seconds (to make testing easier)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	discoverServices()

	// Keep the program running
	for {
		select {
		case <-ticker.C:
			// Re-run service discovery every 10 seconds
			fmt.Println("Re-running service discovery...")
			discoverServices()
		}
	}
}
