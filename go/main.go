package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"golang.org/x/crypto/curve25519"
)

const (
	// defines port number we're using, the service type, and the domain.
	serviceType   = "_ping._tcp"
	serviceDomain = "local."
	serviceName   = "GoPeer"
	servicePort   = 12346
)

var peers []map[string]interface{} // List of dictionaries (maps) to store peer information

var symmkeyGlobal []byte

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

func GenerateEphemeralDHKeyPair() (privKey, pubKey []byte, err error) {
	privKey = make([]byte, 32)
	_, err = rand.Read(privKey) // Generate a new random private key
	if err != nil {
		return nil, nil, err
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	pubKey, err = curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return privKey, pubKey, nil
}

// PKCS7 padding function (same as the one used in Python's Crypto.Util.Padding)
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Encrypt file using AES and HMAC
func encryptFile(key []byte, filename string) error {

	salt := []byte("1234567890abcdef") // 16-byte fixed salt
	iv := []byte("fedcba098b765432")   // 16-byte fixed IV

	// Read the file to be encrypted
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Create AES cipher block and encrypt the plaintext

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Pad the plaintext to ensure it fits in AES block size
	plaintext = pkcs7Padding(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// Calculate HMAC for the ciphertext
	hmacHash := hmac.New(sha256.New, key)
	dataForHMAC := append(append(salt, iv...), ciphertext...)
	fmt.Printf("DATAFORHMAC: %x\n", dataForHMAC)
	fmt.Println("Go HMAC Data Length:", len(dataForHMAC))

	hmacHash.Reset()
	hmacHash.Write(dataForHMAC)
	hmacTag := hmacHash.Sum(nil)
	fmt.Println("Go Data Length:", len(dataForHMAC))
	fmt.Println("Go Key Length:", len(key))
	fmt.Printf("Go HMAC: %x\n", hmacTag)
	fmt.Printf("HII:HMACHash:", hmacHash, "\nkey:", key, "\nciphertext:", ciphertext)

	// Save the encrypted file with salt, IV, HMAC, and ciphertext
	encFile := fmt.Sprintf("%s.enc", filename)
	file, err := os.Create(encFile)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %w", err)
	}
	defer file.Close()
	fmt.Printf("FILE CREATED?")

	_, err = file.Write(salt)
	if err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}

	_, err = file.Write(iv)
	if err != nil {
		return fmt.Errorf("failed to write IV: %w", err)
	}

	_, err = file.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	_, err = file.Write(hmacTag)
	if err != nil {
		return fmt.Errorf("failed to write HMAC: %w", err)
	}

	fmt.Printf("Salt: %s\n", hex.EncodeToString(salt))
	fmt.Printf("IV: %s\n", hex.EncodeToString(iv))
	fmt.Printf("HMAC Tag: %s\n", hex.EncodeToString(hmacTag))
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	fmt.Printf("Derived Key in Go: %x\n", key)
	log.Printf("Encrypted file saved as %s\n", encFile)
	return nil
}

// calculateHMAC computes HMAC-SHA256
func calculateHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// decryptFile decrypts the given encrypted file
func decryptFile(key []byte, filename string) error {
	const (
		SALT_SIZE = 16
		IV_SIZE   = 16
		HMAC_SIZE = 32
	)

	// Read encrypted file
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Ensure the file is at least large enough to contain salt, IV, HMAC, and some ciphertext
	if len(data) < SALT_SIZE+IV_SIZE+HMAC_SIZE {
		return fmt.Errorf("file is too short to be valid")
	}

	// Extract components
	salt := data[:SALT_SIZE]
	iv := data[SALT_SIZE : SALT_SIZE+IV_SIZE]
	ciphertext := data[SALT_SIZE+IV_SIZE : len(data)-HMAC_SIZE]
	hmacTag := data[len(data)-HMAC_SIZE:]

	// Verify HMAC
	saltIVCiphertext := append(append(salt, iv...), ciphertext...)
	calculatedHMAC := calculateHMAC(key, saltIVCiphertext)
	if !hmac.Equal(hmacTag, calculatedHMAC) {
		return fmt.Errorf("HMAC verification failed")
	}
	fmt.Println("HMAC verification successful")

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Decrypt using AES CBC
	if len(ciphertext)%aes.BlockSize != 0 {
		return fmt.Errorf("ciphertext is not a multiple of AES block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Unpad using PKCS7
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return fmt.Errorf("unpadding failed: %w", err)
	}

	// Save decrypted file
	outputFilename := filename[:len(filename)-4] + ".dec"
	err = os.WriteFile(outputFilename, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("failed to save decrypted file: %w", err)
	}

	fmt.Printf("Decrypted file saved as %s\n", outputFilename)
	return nil
}

// pkcs7Unpad removes PKCS7 padding
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	padding := int(data[len(data)-1])
	if padding > blockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
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
	myPriv, myPub, err := GenerateEphemeralDHKeyPair()
	if err != nil {
		log.Println("Error generating ephemeral key pair:", err)
		return
	}

	fmt.Print(myPriv)

	// Send public key in JSON format
	response := map[string]string{
		"public_key": hex.EncodeToString(myPub),
	}
	fmt.Printf("Sending public key (Hex): %s\n", hex.EncodeToString(myPub))

	fmt.Print("RESPONSE: ", response)
	fmt.Printf("GO'S PUBLIC KEY %x\n", hex.EncodeToString(myPub))

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

	// Receive their public key
	theirPubBytes := make([]byte, 512)
	n, err := conn.Read(theirPubBytes)
	if err != nil {
		log.Println("Failed to receive peer public key:", err)
		return
	}

	theirPubHex := string(theirPubBytes[:n]) // Convert bytes to a string
	fmt.Printf("RAW RECEIVED DATA: %q\n", theirPubHex)

	fmt.Printf("Received Public Key (Hex): %s\n", theirPubHex) // Log the received hex string
	// Struct to hold the received JSON data
	var data struct {
		PublicKey string `json:"public_key"`
	}

	// Unmarshal the JSON data into the struct
	errr := json.Unmarshal([]byte(theirPubHex), &data)
	if errr != nil {
		log.Fatalf("Error unmarshalling JSON: %v", errr)
	}

	// Convert the hexadecimal string to a big.Int
	publicKey, ok := new(big.Int).SetString(data.PublicKey[2:], 16) // Remove "0x" prefix and convert to big.Int
	if !ok {
		log.Fatalf("Error converting public key from hex")
	}

	// Print the public key as a big.Int (decimal format)
	fmt.Printf("Public Key (BigInt): %s\n", publicKey.String())

	// Convert received public key from hex
	peerPub, err := hex.DecodeString(data.PublicKey)
	if err != nil {
		log.Println("Failed to decode peer's public key:", err)
		return
	}

	sharedSecret, err := curve25519.X25519(myPriv, peerPub)
	if err != nil {
		log.Println("Failed to compute shared secret:", err)
		return
	}
	log.Println("Derived Shared Secret:", hex.EncodeToString(sharedSecret))

	// Derive symmetric encryption key
	sharedKey := sha256.Sum256(sharedSecret) // Use SHA-256 to derive key

	log.Println("Symmetric Key:", hex.EncodeToString(sharedKey[:]))

	//symmkeyGlobal = sharedKey
	log.Printf("🔑 Secure key derived with %s\n", conn.RemoteAddr())

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
	log.Println("Received file: %s", filename)

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
	timeout := time.After(1 * time.Second)

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
			close(entries) // Close the entries channel to stop the loop
			return
		}
	}
}

func sendFile(peerIP string, peerPort int, filename string, key []byte) {
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

	// Encrypt file
	encryptFile(key, filename)

	// Send the filename and file data
	encryptedFileName := filename + ".enc"
	encryptedFileOpen, err := os.Open(encryptedFileName)
	if err != nil {
		log.Printf("❌ Failed to send filename")
		return
	}

	_, err = conn.Write([]byte(fmt.Sprintf("%s\n", encryptedFileName)))
	if err != nil {
		log.Printf("❌ Failed to send filename")
		return
	}
	_, err = io.Copy(conn, encryptedFileOpen)
	if err != nil {
		log.Printf("❌ Failed to send file data")
		return
	}
	log.Printf("✅ Sent file '%s' to %s:%d", filename, peerIP, peerPort)
}

func selectPeer() *map[string]interface{} {
	var choice int
	fmt.Print("Enter the number of the peer to send the public key to: ")
	_, err := fmt.Scan(&choice)
	if err != nil || choice < 0 || choice >= len(peers) {
		fmt.Println("Invalid selection")
		return nil
	}

	// Return the selected peer
	return &peers[choice]
}

func menu() {
	for {
		// Display the menu
		fmt.Println("Menu:")
		fmt.Println("0. Peer List")
		fmt.Println("1. Key Verification/Transfer")
		fmt.Println("2. Send a File")
		fmt.Println("3. Add File to Share")
		fmt.Println("4. Display Shared Files")
		fmt.Println("5. Request a Shared File")
		fmt.Println("6. Exit")

		var choice int
		_, err := fmt.Scan(&choice)
		if err != nil {
			fmt.Println("Invalid input, please enter a number between 1 and 6.")
			continue
		}

		// Switch based on user's choice
		switch choice {
		case 0: // 0. Peer List
			discoverServices()
		case 1: // 1. Key Verification/Transfer
			discoverServices()
			selectedPeer := selectPeer()
			if selectedPeer == nil {
				log.Println("❌ No valid peer selected. Exiting.")
				return
			}

			peerIP := (*selectedPeer)["IP"].(string)
			peerPort := (*selectedPeer)["Port"].(int)

			conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", peerIP, peerPort))
			if err != nil {
				log.Printf("Error connecting to peer at %s:%d: %v", peerIP, peerPort, err)
				return
			}
			defer conn.Close()

			_, myPub, err := GenerateEphemeralDHKeyPair()
			fmt.Print("MYPUB: ", myPub)
			if err != nil {
				log.Println("Error generating DH key pair:", err)
				return
			}

			response := map[string]string{
				"public_key": hex.EncodeToString(myPub), // Send the public key as a string (hex or decima
			}

			jsonData, err := json.Marshal(response)
			if err != nil {
				log.Println("Error encoding public key to JSON:", err)
				return
			}

			_, err = conn.Write(jsonData)
			if err != nil {
				log.Println("Error sending public key:", err)
				return
			}

			log.Println("Sent public key:", myPub)

			// Handle receiving the peer's public key
			handleConnection(conn)
		case 2: // 2. Send a File
			discoverServices()
			selectedPeer := selectPeer()

			peerIP := (*selectedPeer)["IP"].(string)
			peerPort := (*selectedPeer)["Port"].(int)
			fmt.Printf("📁 Enter the Filename to send to %s:%d: ", peerIP, peerPort)
			var filename string
			fmt.Scan(&filename)
			sendFile(peerIP, peerPort, filename, symmkeyGlobal)
		case 3:
			fmt.Println("You selected Option 3")
		case 4:
			fmt.Println("You selected Option 4")
		case 5:
			fmt.Println("You selected Option 5")
		case 6:
			fmt.Println("Exiting...")
			os.Exit(0) // Exit the program
		default:
			fmt.Println("Invalid Choice. Select a number between 0-6.")
		}

	}
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

	menu()

	// Allow user to select a peer and send a file
	choice := -1
	fmt.Print("\nSelect a peer to send a file to (enter number): ")
	fmt.Scan(&choice)
	if choice >= 0 && choice < len(peers) {
		peer := peers[choice]
		peerIP := peer["IP"].(string)
		peerPort := peer["Port"].(int)
		fmt.Printf("📁 Enter the Filename to send to %s:%d: ", peerIP, peerPort)
		var filename string
		fmt.Scan(&filename)
		fmt.Print("symmkeyglobal: ", symmkeyGlobal)
		sendFile(peerIP, peerPort, filename, symmkeyGlobal)
	} else {
		log.Println("❌ Invalid peer selection")
	}
}
