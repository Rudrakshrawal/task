package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

const (
	channelName   = "mychannel"
	chaincodeName = "chaincode"
)

func main() {
	conn := newGrpcConnection()
	defer conn.Close()

	id := newIdentity()
	sign := newSign()

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(15*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		log.Fatalf("failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	clientID := "Bearer"
	pubKeyPath := "crypto/public.pem"

	if err := uploadClientPubKey(contract, clientID, pubKeyPath); err != nil {
		log.Printf("Warning: could not upload public key: %v", err)
	} else {
		log.Println("Public key check complete.")
	}
	
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("\nSelect task (register / issue / validate / list / revoke / exit): ")
		scanner.Scan()
		task := strings.TrimSpace(strings.ToLower(scanner.Text()))

		switch task {
		case "register":
			fmt.Print("Please enter the path to the NF you want to register: ")
			scanner.Scan()
			nfPath := strings.TrimSpace(scanner.Text())

			if !isValidDirectory(nfPath) {
				fmt.Println(" Invalid directory. Please enter a valid path.")
				continue
			}
			registerNF(contract, nfPath)

		case "issue":
			fmt.Print("Please enter the path to the NF for which you want to issue the token: ")
			scanner.Scan()
			nfPath := strings.TrimSpace(scanner.Text())

			if !isValidDirectory(nfPath) {
				fmt.Println(" Invalid directory. Please enter a valid path.")
				continue
			}
			issueToken(contract, nfPath)

		case "validate":
			fmt.Print("Please enter the path to the NF where the token is stored: ")
			scanner.Scan()
			nfPath := strings.TrimSpace(scanner.Text())

			if !isValidDirectory(nfPath) {
				fmt.Println("Invalid directory. Please enter a valid path.")
				continue
			}
			validateToken(contract, nfPath)

		case "list":
			fmt.Println("Showing all registered Network Functions...")
			result, err := contract.EvaluateTransaction("ShowAllNFs")
			if err != nil {
				fmt.Printf(" Failed to list NFs: %v\n", err)
			} else {
				fmt.Println("Registered Network Functions:\n", string(result))
			}

		case "exit", "quit":
			fmt.Println(" Exiting program gracefully. Goodbye!")
			return

		case "revoke":
			fmt.Print("Please enter the NF ID of the token you want to revoke: ")
			scanner.Scan()
			nfID := strings.TrimSpace(scanner.Text())
		
			// Ensure the NF ID is valid
			if nfID == "" {
				fmt.Println(" Invalid NF ID. Please enter a valid ID.")
				continue
			}
		
			// Call the RevokeToken function
			err := revokeToken(contract, nfID)
			if err != nil {
				fmt.Printf("Failed to revoke token: %v\n", err)
			} else {
				fmt.Println("Token revoked successfully.")
			}
		default:
			fmt.Println(" Invalid task selected. Try again.")
		}
	}
}
