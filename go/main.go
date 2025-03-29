package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/grandcat/zeroconf"
)

const (
	// defines port number we're using, the service type, and the domain.
	serviceType   = "_ping._tcp"
	serviceDomain = "local."
	serviceName   = "GoPeer"
	servicePort   = 12346
)

var peers []map[string]interface{} // List of dictionaries (maps) to store peer information

func getLocalIP() (string, error) {
	// List of network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	// Loop through interfaces to find an IPv4 address
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && !strings.Contains(iface.Name, "loopback") {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			// Look for an IPv4 address
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if ok && ipnet.IP.To4() != nil {
					return ipnet.IP.String(), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no suitable network interface found")
}

func startResponder() (*zeroconf.Server, error) {
	// Find local IP
	ip, err := getLocalIP()
	if err != nil {
		return nil, err
	}

	// Register the Go service with mDNS (zeroconf)
	server, err := zeroconf.Register(
		serviceName,
		serviceType,
		serviceDomain,
		servicePort,
		[]string{"txtvers=1"},
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Service is registered
	log.Printf("Service %s.%s.%s registered on port %d at IP %s\n", serviceName, serviceType, serviceDomain, servicePort, ip)
	return server, nil
}

func startFileReceiver(port int) {
	// Receive files on port
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port)) // Binding to all interfaces
	if err != nil {
		log.Fatalf("Failed to start TCP listener: %v", err)
	}
	log.Printf("Listening for file transfers on TCP port %d...", port)

	// Accept incoming connections
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		// Asynchronously handle each file transfer
		go handleFileTransfer(conn)
	}
}

func handleFileTransfer(conn net.Conn) {
	// Handles collecting file data, and saving it to a file
	defer conn.Close()
	log.Println("Connection established with", conn.RemoteAddr())

	// Read file data, maximum of 4096 bytes
	buffer := make([]byte, 4096)

	// Read the filename
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		log.Println("Failed to read from connection:", err)
		return
	}

	// Split into filename + other data
	parts := string(buffer[:n])
	fileParts := strings.SplitN(parts, "\n", 2)
	if len(fileParts) < 2 {
		log.Println("Invalid file format")
		return
	}

	filename := fileParts[0]
	filedata := []byte(fileParts[1]) // Content after name

	// Create the file to save the data
	f, err := os.Create("received_" + filename)
	if err != nil {
		log.Println("Failed to create file:", err)
		return
	}
	defer f.Close()

	// Write the file data
	_, err = f.Write(filedata)
	if err != nil {
		log.Println("Failed to write file:", err)
		return
	}

	// Log success and close the connection
	log.Printf("✅|Received file '%s' from %s", filename, conn.RemoteAddr().String())
}

func discoverServices() {
	// Create a new Zeroconf service resolver
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatal("Failed to create resolver: ", err)
	}

	// Discover all _ping._tcp. peers
	serviceType := "_ping._tcp." // Match the service type advertised by Python and Go peers

	// Create a context to pass to the resolver
	ctx := context.Background()

	// Start the service resolution in the background
	entries := make(chan *zeroconf.ServiceEntry)

	// Reset the peers list before starting a new discovery cycle
	peers = []map[string]interface{}{}

	// Discover services of type "_ping._tcp" on my computer (synchronously now)
	err = resolver.Browse(ctx, serviceType, "", entries)
	if err != nil {
		log.Fatal("Error starting service browse: ", err)
	}

	// Timeout mechanism to stop waiting if no peers are found within 10 seconds
	timeout := time.After(10 * time.Second)

	fmt.Println("Peers:")
	index := 0

	// Process the entries from the channel or timeout
	for {
		select {
		case entry := <-entries:
			// Service discovered, add to the list
			peer := map[string]interface{}{
				"Name": entry.Service,
				"IP":   entry.AddrIPv4[0].String(),
				"Port": entry.Port,
			}
			peers = append(peers, peer)
			fmt.Printf("[%d] %s at %s:%d\n", index, entry.Service, entry.AddrIPv4[0], entry.Port)
			index++

		case <-timeout:
			// Timeout reached, stop waiting for services
			fmt.Println("Timeout reached, finishing discovery.")
			fmt.Println("Finish printing all of the peers")
			close(entries) // Close the entries channel to stop the loop
			return
		}
	}
}

func sendFile(peerIP string, peerPort int, filename string) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("❌File '%s' not found", filename)
		return
	}
	defer file.Close()

	// Connect
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", peerIP, peerPort))
	if err != nil {
		log.Printf("❌Could not connect to peer at %s:%d", peerIP, peerPort)
		return
	}
	defer conn.Close()

	// Send the filename and file data
	_, err = conn.Write([]byte(fmt.Sprintf("%s\n", filename)))
	if err != nil {
		log.Printf("❌ Failed to send filename")
		return
	}
	_, err = io.Copy(conn, file)
	if err != nil {
		log.Printf("❌ Failed to send file data")
		return
	}
	log.Printf("✅ Sent file '%s' to %s:%d", filename, peerIP, peerPort)
}

func main() {
	// Shutdown handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Start the mDNS service discovery
	server, err := startResponder()
	if err != nil {
		log.Fatal(err)
	}
	defer server.Shutdown()

	// Start listening for incoming file transfers
	go startFileReceiver(servicePort)

	// Re-run the searcher every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Discover services
	discoverServices()
	fmt.Print("HELLLLO")

	// Allow user to select a peer and send a file
	choice := -1
	fmt.Print("\nSelect a peer to send a file to (enter number): ")
	fmt.Scan(&choice)
	if choice >= 0 && choice < len(peers) {
		peer := peers[choice]
		peerIP := peer["IP"].(string)
		peerPort := peer["Port"].(int)
		fmt.Printf("Enter the filename to send to %s:%d: ", peerIP, peerPort)
		var filename string
		fmt.Scan(&filename)
		sendFile(peerIP, peerPort, filename)
	} else {
		log.Println("❌ Invalid peer selection")
	}

}
