// +build example3

package main

import (
	"fmt"
	"sync"
	HMAC_env "tmp/src/HMAC/core"
	seed_env "tmp/src/SeedGeneration/core"
	zkx "tmp/src/ZeroKnowledge/core"
	zkx_models "tmp/src/ZeroKnowledge/models"
)

var DEBUG = true

// Print a message if debugging is enabled
func printMsg(who string, message string) {
	if DEBUG {
		fmt.Printf("[%s] %s\n", who, message)
	}
}

// Client function for Zero Knowledge Proof interaction
func client(clientSocket chan string, serverSocket chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	printMsg("client", "Initializing ZeroKnowledge object")
	clientObject := zkx.New("Ed25519", "blake2b", nil, "HB2B", 16)

	// Generate and send a signature for the client identity
	printMsg("client", "Generating signature for identity 'John'")
	identity := "John"
	signature := clientObject.CreateSignature(identity)
	serverSocket <- zkx_models.ZeroKnowledgeSignature.ToJSON(signature)
	printMsg("client", fmt.Sprintf("Sent signature: %s", zkx_models.ZeroKnowledgeSignature.ToJSON(signature)))

	// Receive token from the server
	printMsg("client", "Waiting to receive token from server")
	token := <-clientSocket
	printMsg("client", fmt.Sprintf("Received token: %s", token))

	// Generate and send proof using the received token
	printMsg("client", "Generating proof using received token")
	proof := zkx_models.ZeroKnowledgeSignature.ToJSON(clientObject.Sign(identity, token))
	printMsg("client", fmt.Sprintf("Proof: %s", proof))
	serverSocket <- proof

	// Receive result from the server
	printMsg("client", "Waiting to receive result from server")
	result := <-clientSocket
	printMsg("client", fmt.Sprintf("Result: %s", result))

	if result == "Verification successful" {
		printMsg("client", "Server verification successful, proceeding with seed generation")
		// Generate a main seed and create an HMAC client
		mainSeed := seed_env.NewSeedGenerator("jack").Generate()
		printMsg("client", fmt.Sprintf("Generated main seed: %s", mainSeed))
		obj := HMAC_env.NewHMACClient("sha256", mainSeed, 1)
		obj.InitDecryptDict()

		// Send the main seed to the server
		printMsg("client", "Sending main seed to server")
		serverSocket <- string(mainSeed)

		// If server acknowledges receipt of the seed, proceed with message exchange
		printMsg("client", "Waiting for server acknowledgment of seed receipt")
		if <-clientSocket == obj.EncryptMessage("") {
			printMsg("client", "Server acknowledged seed receipt")
			message := "hello"
			printMsg("client", fmt.Sprintf("Sending encrypted message to server: %s", message))
			serverSocket <- obj.EncryptMessageByChunks(message)

			printMsg("client", "Waiting for server response")
			if <-clientSocket == obj.EncryptMessage(message) {
				printMsg("client", "Server has successfully decrypted the message")
			}
		}
	}
}

// Server function for Zero Knowledge Proof interaction
func server(serverSocket chan string, clientSocket chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	printMsg("server", "Initializing ZeroKnowledge object")
	serverPassword := "SecretServerPassword"
	serverZK := zkx.New("Ed25519", "blake2b", nil, "HB2B", 16)

	// Receive client signature
	printMsg("server", "Waiting to receive client signature")
	clientSig := <-serverSocket
	clientSignature := zkx_models.ZeroKnowledgeSignature.FromJSON(clientSig)
	printMsg("server", fmt.Sprintf("Received client signature: %s", clientSignature))

	// Generate and send token to the client
	printMsg("server", "Generating token for client")
	token := serverZK.Sign(serverPassword, zkx.Token(serverZK))
	printMsg("server", fmt.Sprintf("Generated token: %s", token))
	clientSocket <- zkx_models.ZeroKnowledgeData.ToJSON(token)

	// Receive proof from the client
	printMsg("server", "Waiting to receive proof from client")
	proof := <-serverSocket
	clientProof := zkx_models.ZeroKnowledgeData.FromJSON(proof)
	printMsg("server", fmt.Sprintf("Received proof: %s", proof))

	// Verify the proof
	printMsg("server", "Verifying proof")
	tokenData := zkx_models.ZeroKnowledgeData.FromJSON(clientProof.Data)
	serverVerification := serverZK.Verify(tokenData, clientSignature)
	printMsg("server", fmt.Sprintf("Server verification result: %t", serverVerification))

	if !serverVerification {
		clientSocket <- "Server verification failed"
		printMsg("server", "Server verification failed")
	} else {
		clientVerification := clientSignature.Verify(clientProof, tokenData)
		printMsg("server", fmt.Sprintf("Client verification result: %t", clientVerification))

		if clientVerification {
			clientSocket <- "Verification successful"
			printMsg("server", "Client verification successful")

			// Receive the main seed from the client
			printMsg("server", "Waiting to receive main seed from client")
			mainSeed := <-serverSocket
			obj := HMAC_env.NewHMACClient("sha256", []byte(mainSeed), 1)
			obj.InitDecryptDict()

			// Acknowledge receipt of the seed
			printMsg("server", "Acknowledging receipt of the seed")
			clientSocket <- obj.EncryptMessage("")

			// Receive and decrypt the message from the client
			printMsg("server", "Waiting to receive encrypted message from client")
			clientMsg := <-serverSocket
			printMsg("server", fmt.Sprintf("Received encrypted message: %s", clientMsg))
			msg := obj.DecryptMessageByChunks(clientMsg)
			printMsg("server", fmt.Sprintf("Decrypted message: %s", msg))

			// Send the decrypted message back to the client
			printMsg("server", "Sending decrypted message back to client")
			clientSocket <- obj.EncryptMessageByChunks(msg)
		} else {
			clientSocket <- "Verification failed"
			printMsg("server", "Client verification failed")
		}
	}
}

// Entry point of the program
func main() {
	clientSocket := make(chan string) // Create an unbuffered channel for client
	serverSocket := make(chan string) // Create an unbuffered channel for server
	var wg sync.WaitGroup             // Declare a WaitGroup
	wg.Add(2)                         // Increment the WaitGroup counter by 2

	printMsg("main", "Starting client and server goroutines")

	go func() {
		defer close(clientSocket)
		defer close(serverSocket)
		wg.Wait() // Wait for all goroutines to finish
	}()

	go client(clientSocket, serverSocket, &wg) // Start the client goroutine
	go server(serverSocket, clientSocket, &wg) // Start the server goroutine

	wg.Wait() // Wait until all goroutines are finished

	printMsg("main", "Client and server goroutines finished")
}
