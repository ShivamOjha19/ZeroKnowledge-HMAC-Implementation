// +build example2

package main

import (
	"fmt"
	"sync"
	zkx "tmp/src/ZeroKnowledge/core"
	zkx_models "tmp/src/ZeroKnowledge/models"
)

var debugEnabled = true

func logMessage(source string, msg string) {
	if debugEnabled {
		fmt.Printf("[%s] %s\n", source, msg)
	}
}

func runClient(cliChan chan string, srvChan chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Create a ZeroKnowledge object for the client
	clientObject, err := zkx.New("Ed25519", "blake2b", nil, "HB2B", 16)
	if err != nil {
		logMessage("client", fmt.Sprintf("Failed to create ZeroKnowledge object: %v", err))
		return
	}
	logMessage("client", "Created ZeroKnowledge object for client")

	// Generate a signature for the client identity
	identity := "John"
	signature := clientObject.CreateSignature([]byte(identity))
	logMessage("client", fmt.Sprintf("Generated signature for identity '%s': %v", identity, signature))

	// Send the signature to the server
	signatureJSON := signature.ToJSON()
	srvChan <- signatureJSON
	logMessage("client", fmt.Sprintf("Sent signature to server: %s", signatureJSON))

	// Receive token from the server
	token := <-cliChan
	logMessage("client", fmt.Sprintf("Received token from server: %s", token))

	// Generate and send proof to the server
	proof := clientObject.Sign([]byte(identity), token)
	proofJSON := proof.ToJSON()
	logMessage("client", fmt.Sprintf("Generated proof: %s", proofJSON))
	srvChan <- proofJSON
	logMessage("client", fmt.Sprintf("Sent proof to server: %s", proofJSON))

	// Receive and log result from the server
	result := <-cliChan
	logMessage("client", fmt.Sprintf("Received result from server: %s", result))
}

func runServer(srvChan chan string, cliChan chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Set the server password
	serverPassword := "SecretServerPassword"
	logMessage("server", "Set server password")

	// Create a ZeroKnowledge object for the server
	serverZK, err := zkx.New("Ed25519", "blake2b", nil, "HB2B", 16)
	if err != nil {
		logMessage("server", fmt.Sprintf("Failed to create ZeroKnowledge object: %v", err))
		return
	}
	logMessage("server", "Created ZeroKnowledge object for server")

	// Receive client signature
	clientSig := <-srvChan
	clientSignature := zkx_models.ZeroKnowledgeSignature{}
	if err := clientSignature.FromJSON(clientSig); err != nil {
		logMessage("server", fmt.Sprintf("Failed to parse client signature: %v", err))
		return
	}
	logMessage("server", fmt.Sprintf("Received client signature: %v", clientSignature))

	// Generate and send token to the client
	token, err := zkx.Token(*serverZK)
	if err != nil {
		logMessage("server", fmt.Sprintf("Failed to generate token: %v", err))
		return
	}
	tokenData := serverZK.Sign([]byte(serverPassword), token)
	tokenJSON := tokenData.ToJSON()
	logMessage("server", fmt.Sprintf("Generated token: %s", tokenJSON))
	cliChan <- tokenJSON
	logMessage("server", "Sent token to client")

	// Receive and verify proof from the client
	proof := <-srvChan
	clientProof := zkx_models.ZeroKnowledgeData{}
	if err := clientProof.FromJSON(proof); err != nil {
		logMessage("server", fmt.Sprintf("Failed to parse client proof: %v", err))
		return
	}
	logMessage("server", fmt.Sprintf("Received proof from client: %s", proof))

	// Verify the received proof
	serverVerification := serverZK.Verify(tokenData, clientSignature, clientProof)
	logMessage("server", fmt.Sprintf("Server verification result: %t", serverVerification))

	// Send verification result to the client
	if !serverVerification {
		logMessage("server", "Server verification failed")
		cliChan <- "Server verification failed"
	} else {
		clientVerification := clientSignature.Verify(clientProof, tokenData)
		logMessage("server", fmt.Sprintf("Client verification result: %t", clientVerification))
		if clientVerification {
			logMessage("server", "Client verification successful")
			cliChan <- "Verification successful"
		} else {
			logMessage("server", "Client verification failed")
			cliChan <- "Verification failed"
		}
	}
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
