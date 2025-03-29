package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/grandcat/zeroconf"
)

const (
	// defines port number we're using, the service type, and the domain.
	serviceType   = "_ping._tcp"
	serviceDomain = "local."
	serviceName   = "GoPeer"
	servicePort   = 12346
)

func getLocalIP() (string, error) {
	// List of network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	// Loop through interfaces to find an IPv4 address
	// We'll use that address for our communications
	// This was a mix-mash of a ton of functions that did this to varying degrees
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && !strings.Contains(iface.Name, "loopback") {
			addrs, err := iface.Addrs()
			if err != nil {
				// if an error occurs
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
		// Asnyconously handle each file transfer
		// That way the entire program doesn't buffer when a file is sent
		go handleFileTransfer(conn)
	}
}

func handleFileTransfer(conn net.Conn) {
	// Handles collecting file data, and saving it to a file

	// Close the connection later
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

	log.Printf("Received file: %s", filename)

	// Create the file to save the data
	// Using a "recieved_" value to make it obvious
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
	// I like emojis now :]
	log.Printf("✅|Received file '%s' from %s\n", filename, conn.RemoteAddr().String())
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
	startFileReceiver(servicePort)

	// Log info and wait for shutdown signal
	log.Println("Go MDMS peer running. Press Ctrl+C to stop.")
	<-sig
	log.Println("Shutting down...")
}
