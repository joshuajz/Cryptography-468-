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
	//"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// defines port number we're using, the service type, and the domain.
	serviceType   = "_ping._tcp"
	serviceDomain = "local."
	serviceName   = "GoPeer"
	servicePort   = 12346
)

var peers []map[string]interface{} // List of dictionaries (maps) to store peer information
var (
	// Predefined DH parameters
	p, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
	g = big.NewInt(2)
) // Message buffer to store logs and predefined DH parameters

var keysMap map[string][]byte
var sharedFiles [][]string

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
	// Calculate the shared secret using Diffie-Hellman
	shared := new(big.Int).Exp(theirPub, myPriv, p)

	// Return the raw bytes of the shared secret (no hashing)
	return shared.Bytes()
}

// deriveKey derives a cryptographic key from the shared secret using scrypt
func deriveKey(sharedSecret []byte) ([]byte, []byte, error) {
	// Generate a random salt (16 bytes)
	salt := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	key := pbkdf2.Key(sharedSecret, salt, 100000, 32, sha256.New)
	fmt.Printf("Go Derived Key: %x\n", key)

	fmt.Printf("GO SHARED SECRET: %x\n", sharedSecret)
	fmt.Printf("GO DERIVED KEY: %x\n", key)

	return key, salt, nil
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
	//fmt.Printf("Symmetric Key: %s\n", key)
	fmt.Printf("Derived Key in Go: %x\n", key)

	//fmt.Printf("Encrypted File Information:\nsalt: %s\niv: %s\nhmacTag: %s\nciphertext: %s\n", salt, iv, hmacTag, ciphertext)

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
		fmt.Println("CALLING HANDLE CONNECTIONS FUNCTION")
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 4096) // Buffer to receive data

	// Read incoming data
	n, err := conn.Read(buffer)
	if err != nil {
		log.Println("Error reading data:", err)
		return
	}

	data := buffer[:n]

	// Try to parse the data as JSON to check if it's a public key
	var message map[string]string
	err = json.Unmarshal(data, &message)
	clientIP := conn.RemoteAddr().String()

	fmt.Printf("Parsed JSON: %s\n\n", message)
	fmt.Printf("Does the value exist?: %s", message["request"])

	if err == nil && message["public_key"] != "" {
		// If it's a public key, store it
		log.Printf("Received public key from %s: %s", clientIP, message["public_key"])

		myPriv, myPub := generateDHKeyPair()

		// Send GO's public key back to the other peer
		response := map[string]string{
			"public_key": myPub.String(), // SEnt key as a hexadecimal string
		}

		// Convert the response into JSON
		jsonData, err := json.Marshal(response)
		if err != nil {
			log.Println("Error encoding JSON:", err)
			return
		}

		_, err = conn.Write(jsonData)
		if err != nil {
			log.Println("Error sending public key:", err)
			return
		}

		log.Printf("Sent public key to %s: %s", clientIP, myPub.String())

		// publicKey, ok := new(big.Int).SetString(data.PublicKey[2:], 16) // Remove "0x" prefix and convert to big.Int

		// Now compute the shared secret using the other peer's public key
		peerPub, ok := new(big.Int).SetString(message["public_key"][2:], 16)
		if !ok {
			log.Println("Failed to convert peer's public key")
			return
		}

		// Calculate shared secret using Diffie-Hellman formula
		sharedSecret := computeSharedSecret(peerPub, myPriv)

		// Derive symmetric key from the shared secret
		symmKey, _, err := deriveKey(sharedSecret)
		if err != nil {
			log.Println("Error deriving symmetric key:", err)
			return
		}

		// Store the symmetric key for future use
		keysMap[clientIP] = symmKey
		log.Printf("Symmetric key derived and stored for %s", clientIP)
		return
	}
	if err == nil && message["request"] == "file_list" {
		// Return back a list of all files added to be shared
		response := map[string]interface{}{
			"files": sharedFiles,
		}

		jsonData, err := json.Marshal(response)
		if err != nil {
			log.Println("Error encoding JSON:", err)
			return
		}

		fmt.Printf("JSON DATA: %s, %v", string(jsonData), jsonData)

		_, err = conn.Write(jsonData)
		if err != nil {
			log.Println("Error sending file list:", err)
			return
		}

		_, err = conn.Write(jsonData)
		if err != nil {
			log.Println("Error sending file list:", err)
			return
		}
		fmt.Printf("\nSuccessfully wrote jsondata\n")
		return
	}

	// If it's not a public key, assume it's a file
	log.Println("Receiving file data from", clientIP)

	// File data should be in the form of filename + newline + file data
	parts := bytes.SplitN(data, []byte("\n"), 2)
	if len(parts) < 2 {
		log.Println("Invalid file format")
		return
	}

	filename := string(parts[0])
	filedata := parts[1]

	// Save the file data to disk
	file, err := os.Create("received_" + filename)
	if err != nil {
		log.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	_, err = file.Write(filedata)
	if err != nil {
		log.Println("Error writing file:", err)
		return
	}

	// Decrypt the file using the symmetric key
	if keysMap[clientIP] == nil {
		log.Println("No symmetric key available for decryption")
		return
	}

	// Decrypt the file
	decryptFile(keysMap[clientIP], "received_"+filename)
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
		fmt.Println("5. Request Shared File List")
		fmt.Println("6. Request a Shared File")
		fmt.Println("7. Exit")

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

			_, myPub := generateDHKeyPair()
			response := map[string]string{
				"public_key": myPub.String(), // Send the public key as a string (hex or decimal)
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

			log.Println("Sent public key:", myPub.String())

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
			sendFile(peerIP, peerPort, filename, keysMap[peerIP])
		case 3: // 3. Add a file to share
			fmt.Printf("📁 Enter the Filename to share: ")
			var filename string
			fmt.Scan(&filename)

			file, err := os.Open(filename)
			if err != nil {
				fmt.Errorf("failed to open file: %w", err)
				return
			}
			defer file.Close()

			// Create a new SHA-256 hash object
			hash := sha256.New()

			// Copy the file's content into the hash object
			_, err = io.Copy(hash, file)
			if err != nil {
				fmt.Errorf("failed to copy file content to hash: %w", err)
				return
			}
			hexString := fmt.Sprintf("%x", hash.Sum(nil))
			fileAdd := []string{filename, hexString}
			sharedFiles = append(sharedFiles, fileAdd)
			fmt.Printf("📁 Added to shared list: %s (%s)", filename, hexString)
			hash.Sum(nil)
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
	keysMap = make(map[string][]byte)
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
}
