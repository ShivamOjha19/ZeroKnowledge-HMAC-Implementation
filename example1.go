// +build example1

package main

import (
	"fmt"
	"sync"
	hmacCore "tmp/src/HMAC/core"
	seedGen "tmp/src/SeedGeneration/core"
)

var debugEnabled = true

func logMessage(source string, msg string) {
	if debugEnabled {
		fmt.Printf("[%s] %s\n", source, msg)
	}
}

func runClient(cliChan chan string, srvChan chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Generate seed and initialize HMAC client
	seed := seedGen.NewSeedGenerator("jack").Generate()
	logMessage("client", fmt.Sprintf("Generated seed: %x", seed))
	hmacClient := hmacCore.NewHMACClient("sha256", seed, 1)
	hmacClient.InitDecryptDict()
	logMessage("client", "Initialized HMAC client with generated seed")

	// Send seed to server
	srvChan <- string(seed)
	logMessage("client", fmt.Sprintf("Sent seed to server: %x", seed))

	// Receive acknowledgment from server
	serverAck := <-cliChan
	logMessage("client", fmt.Sprintf("Received acknowledgment from server: %s", serverAck))

	// Verify server acknowledgment
	if serverAck == hmacClient.EncryptMessage("") {
		message := "hello"
		encryptedMessage := hmacClient.EncryptMessageByChunks(message)
		srvChan <- encryptedMessage
		logMessage("client", fmt.Sprintf("Sent encrypted message to server: %s", encryptedMessage))

		// Receive server's response
		serverResponse := <-cliChan
		logMessage("client", fmt.Sprintf("Received server response: %s", serverResponse))

		// Verify server's decrypted response
		if serverResponse == hmacClient.EncryptMessage(message) {
			logMessage("client", "Server has successfully decrypted the message")
		} else {
			logMessage("client", "Server failed to decrypt the message correctly")
		}
	} else {
		logMessage("client", "Failed to receive valid acknowledgment from server")
	}
}

func runServer(srvChan chan string, cliChan chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Receive seed from client
	seed := <-srvChan
	logMessage("server", fmt.Sprintf("Received seed from client: %x", seed))
	hmacClient := hmacCore.NewHMACClient("sha256", []byte(seed), 1)
	hmacClient.InitDecryptDict()
	logMessage("server", "Initialized HMAC client with received seed")

	// Send acknowledgment to client
	clientAck := hmacClient.EncryptMessage("")
	cliChan <- clientAck
	logMessage("server", fmt.Sprintf("Sent acknowledgment to client: %s", clientAck))

	// Receive encrypted message from client
	encryptedMessage := <-srvChan
	logMessage("server", fmt.Sprintf("Received encrypted message from client: %s", encryptedMessage))

	// Decrypt message
	decryptedMessage := hmacClient.DecryptMessageByChunks(encryptedMessage)
	logMessage("server", fmt.Sprintf("Decrypted message: %s", decryptedMessage))

	// Send decrypted message back to client
	encryptedResponse := hmacClient.EncryptMessageByChunks(decryptedMessage)
	cliChan <- encryptedResponse
	logMessage("server", fmt.Sprintf("Sent encrypted response back to client: %s", encryptedResponse))
}

func main() {
	cliChan := make(chan string)
	srvChan := make(chan string)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer close(cliChan)
		defer close(srvChan)
		wg.Wait()
		logMessage("main", "All goroutines finished execution")
	}()

	go runClient(cliChan, srvChan, &wg)
	go runServer(srvChan, cliChan, &wg)

	wg.Wait()
	logMessage("main", "Main function finished execution")
}
