package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/grandcat/zeroconf"
	"golang.org/x/crypto/scrypt"
)

const (
	// defines port number we're using, the service type, and the domain.
	serviceType   = "_ping._tcp"
	serviceDomain = "local."
	serviceName   = "GoPeer"
	servicePort   = 12346
)

var (
	MESSAGE_BUFFER []string

	// Predefined DH parameters
	p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
	g = big.NewInt(2)
) // Message buffer to store logs and predefined DH parameters

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

func generateDHKeyPair() (*big.Int, *big.Int) {
	priv, _ := rand.Int(rand.Reader, p)
	pub := new(big.Int).Exp(g, priv, p)
	return priv, pub
}

func computeSharedSecret(theirPub, myPriv *big.Int) []byte {
	shared := new(big.Int).Exp(theirPub, myPriv, p)
	hash := sha256.Sum256(shared.Bytes())
	return hash[:]
}

// deriveKey derives a cryptographic key from the shared secret using scrypt
func deriveKey(sharedSecret []byte) ([]byte, []byte, error) {
	// Generate a random salt (16 bytes)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive a 32-byte key using scrypt
	key, err := scrypt.Key(sharedSecret, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	return key, salt, nil
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
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Println("Connection established with", conn.RemoteAddr())

	// Diffie-Hellman Key Exchange
	myPriv, myPub := generateDHKeyPair()
	conn.Write(myPub.Bytes())

	response := map[string]string{
		"public_key": myPub.Text(16), // Send key as a hexadecimal string
	}
	jsonData, err := json.Marshal(response)
	if err != nil {
		log.Println("Error encoding JSON:", err)
		return
	}

	// Send JSON to client
	_, err = conn.Write(jsonData)
	if err != nil {
		log.Println("Error sending JSON:", err)
		return
	}
	log.Println("Sent JSON:", string(jsonData)) // Debugging output

	theirPubBytes := make([]byte, 256)
	n, err := conn.Read(theirPubBytes)
	if err != nil {
		log.Println("Failed to receive peer public key:", err)
		return
	}

	// Parse JSON from client
	var clientData map[string]string
	err = json.Unmarshal(theirPubBytes[:n], &clientData)
	if err != nil {
		log.Println("Failed to parse JSON:", err)
		return
	}
	theirPub := new(big.Int).SetBytes(theirPubBytes)
	sharedSecret := computeSharedSecret(theirPub, myPriv)

	key, salt, err := deriveKey(sharedSecret)
	if err != nil {
		log.Println("Failed to derive key:", err)
		return
	}
	log.Printf("Derived key: %x\n", key)
	log.Printf("Using salt: %x\n", salt)
	log.Printf("🔑 Secure key derived with %s\n", conn.RemoteAddr())

	// File transfer
	buffer := make([]byte, 4096)
	n, err = conn.Read(buffer)
	if err != nil && err != io.EOF {
		log.Println("Failed to read file data:", err)
		return
	}
	parts := string(buffer[:n])
	fileParts := strings.SplitN(parts, "\n", 2)
	if len(fileParts) < 2 {
		log.Println("Invalid file format")
		return
	}
	filename := fileParts[0]
	filedata := []byte(fileParts[1])
	MESSAGE_BUFFER = append(MESSAGE_BUFFER, fmt.Sprintf("Received file: %s", filename))
	f, err := os.Create("received_" + filename)
	if err != nil {
		log.Println("Failed to create file:", err)
		return
	}
	defer f.Close()
	_, err = f.Write(filedata)
	if err != nil {
		log.Println("Failed to write file:", err)
		return
	}
	MESSAGE_BUFFER = append(MESSAGE_BUFFER, fmt.Sprintf("✅|Received file '%s' from %s", filename, conn.RemoteAddr().String()))
}

func clearTerminal() {
	// ANSI escape code to clear the terminal
	fmt.Print("\033[H\033[2J")
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

	go func() {
		// Discover services of type "_ping._tcp" on my computer
		if err := resolver.Browse(ctx, serviceType, "", entries); err != nil {
			log.Fatal("Error starting service browse: ", err)
		}
		fmt.Printf("Peers:\n")

		index := 0
		// Listen for discovered services and print their details
		for entry := range entries {
			fmt.Printf("[%d] %s at %s:%d\n", index, entry.HostName, entry.AddrIPv4[0], entry.Port)
			index++
		}
	}()
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

	// Run initial discovery and periodic discovery
	discoverServices()

	// Keep the program running and perform service discovery at the interval
	for {
		select {
		case <-ticker.C:
			// Re-run service discovery every 10 seconds
			clearTerminal()
			discoverServices()

			// Print message buffer
			fmt.Println("\nLogs:")
			for _, msg := range MESSAGE_BUFFER {
				fmt.Println(msg)
			}
			fmt.Println("\n")
		case <-sig:
			// Handle shutdown signal
			log.Println("Shutting down...")
			return
		}
	}
}
