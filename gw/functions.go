package main

import (
	"encoding/json"
	"fmt"
	"os"
	"errors"
	"path/filepath"
	"time"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	//for tbales
	"text/tabwriter"


)


type TokenPayload struct {
	NFInstanceID string `json:"nfInstanceId"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
	IssuerID   string `json:"iss"`  // Issuer ID
	AudienceID string `json:"aud"`
}






// Helper to check if a path is a valid directory
func isValidDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func registerNF(contract *client.Contract, nfPath string) {
	nfData, err := os.ReadFile(filepath.Join(nfPath, "profile.json"))
	if err != nil {
		panic(fmt.Errorf("failed to read NF profile: %w", err))
	}

	pubKeyData, err := os.ReadFile(filepath.Join(nfPath, "public.pem"))
	if err != nil {
		panic(fmt.Errorf("failed to read public key: %w", err))
	}

	var nf map[string]interface{}
	_ = json.Unmarshal(nfData, &nf)
	nfID := nf["nfInstanceId"].(string)

	existing, err := contract.EvaluateTransaction("GetNFPubKey", nfID)
	if err == nil && len(existing) > 0 {
		fmt.Printf("NF with ID '%s' is already registered.\n", nfID)
		return
	}



	_, err = contract.SubmitTransaction("RegisterNF", nfID, string(nfData), string(pubKeyData))
	if err != nil {
		panic(fmt.Errorf("failed to register NF: %w", err))
	}
	fmt.Println("NF registered successfully with public key.\n\n")

	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "Field\tValue")
	fmt.Fprintln(writer, "-----\t-----")

	for key, value := range nf {
		fmt.Fprintf(writer, "%s\t%v\n", key, value)
	}

	writer.Flush()

}










func issueToken(contract *client.Contract, nfcPath string) {
	// Step 1: Load profile.json of requesting NF (NFC)
	profileData, _ := os.ReadFile(filepath.Join(nfcPath, "profile.json"))
	var nf map[string]interface{}
	_ = json.Unmarshal(profileData, &nf)
	issuerID := nf["nfInstanceId"].(string)

	// Step 2: Ask for the NF type (or ID) that NFC wants to talk to
	var audienceType string
	fmt.Print("Enter target NF type to request access to: ")
	fmt.Scanln(&audienceType)

	// Step 3: Find the first matching NF by type
	nfsDir := "../nfs"
	entries, _ := os.ReadDir(nfsDir)
	var audienceID string

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profilePath := filepath.Join(nfsDir, entry.Name(), "profile.json")
		data, err := os.ReadFile(profilePath)
		if err != nil {
			continue
		}
		var candidate map[string]interface{}
		_ = json.Unmarshal(data, &candidate)
		if candidate["nfType"] == audienceType {
			audienceID = candidate["nfInstanceId"].(string)
			break
		}
	}

	if audienceID == "" {
		fmt.Printf("No NF found with type '%s'.\n", audienceType)
		return
	}

	if issuerID == audienceID {
		fmt.Println("Error: Cannot issue a token to itself.")
		return
	}

	// Step 4: Validate NFP is registered
	_, err := contract.EvaluateTransaction("GetNFPubKey", audienceID)
	if err != nil {
		fmt.Printf("Target NF (ID: %s) not registered.\n", audienceID)
		return
	}

	// Step 5: Load MAIN’s private key (in same dir as main.go)
	mainPrivateKeyPath := "crypto/private.pem"
	privateKey, err := LoadRSAPrivateKeyFromFile(mainPrivateKeyPath)
	if err != nil {
		panic(fmt.Errorf("main.go failed to load its private key: %w", err))
	}

	// Step 6: Create the JWT
	payload := TokenPayload{
		NFInstanceID: issuerID,
		IssuerID:     "Bearer", // main.go is signing
		AudienceID:   audienceID,
		IssuedAt:     time.Now().Unix(),
		ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
	}

	header := base64.StdEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadJSON, _ := json.Marshal(payload)
	payloadEncoded := base64.StdEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payloadEncoded

	hashed := sha256.Sum256([]byte(signingInput))
	signature, _ := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed[:])
	sigEncoded := base64.StdEncoding.EncodeToString(signature)

	token := signingInput + "." + sigEncoded

	// Step 7: Upload token to blockchain for tracking & expiry check
	_, err = contract.SubmitTransaction("UploadToken", audienceID, token)
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	// Step 8: Save token locally to NFC’s tokens dir
	tokensPath := filepath.Join(nfcPath, "tokens")
	_ = os.MkdirAll(tokensPath, os.ModePerm)

	i := 1
	var tokenFile string
	for {
		tokenFile = filepath.Join(tokensPath, fmt.Sprintf("jwt%d.json", i))
		if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
			break
		}
		i++
	}

	if err := os.WriteFile(tokenFile, []byte(token), 0644); err != nil {
		fmt.Printf("Error writing token file: %v\n", err)
	} else {
		fmt.Printf("Token saved as %s\n", tokenFile)
	}
	fmt.Println("Token issued and signed by bearer .")
}



func uploadClientPubKey(contract *client.Contract, clientID string, pubKeyPath string) error {
	// Check if public key already exists on-chain
	existingKey, err := contract.EvaluateTransaction("GetClientPubKey", clientID)
	if err == nil && len(existingKey) > 0 {
		fmt.Println("Public key already exists on blockchain, skipping upload.")
		return nil
	}


	fmt.Printf("Existing key found: [%s]\n", string(existingKey))


	// Otherwise, upload
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	_, err = contract.SubmitTransaction("RegisterClientPubKey", clientID, string(pubKeyData))
	if err != nil {
		return fmt.Errorf("failed to upload client public key to ledger: %w", err)
	}

	fmt.Println("Client public key successfully uploaded to blockchain.")
	return nil
}



func validateToken(contract *client.Contract, nfPath string) {
	tokensDir := filepath.Join(nfPath, "tokens")

	files, err := os.ReadDir(tokensDir)
	if err != nil {
		fmt.Println("Error accessing tokens directory:", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("No tokens found in this NF's directory. Issue one first!")
		return
	}

	var latestFile string
	var maxIndex int
	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "jwt") && strings.HasSuffix(name, ".json") {
			var index int
			_, err := fmt.Sscanf(name, "jwt%d.json", &index)
			if err == nil && index > maxIndex {
				maxIndex = index
				latestFile = name
			}
		}
	}

	if latestFile == "" {
		fmt.Println("No valid jwt*.json files found.")
		return
	}

	tokenPath := filepath.Join(tokensDir, latestFile)
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		fmt.Printf("Failed to read token file %s: %v\n", latestFile, err)
		return
	}

	// Step 1: Parse JWT
	parts := strings.Split(string(tokenData), ".")
	if len(parts) != 3 {
		fmt.Println("Invalid token format. Deleting:", latestFile)
		_ = os.Remove(tokenPath)
		return
	}

	// Step 2: Decode and parse payload
	payloadJSON, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Println("Corrupt token payload. Deleting:", latestFile)
		_ = os.Remove(tokenPath)
		return
	}

	var payload TokenPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		fmt.Println("Invalid token structure. Deleting:", latestFile)
		_ = os.Remove(tokenPath)
		return
	}

	// Step 3: Check expiry
	if time.Now().Unix() > payload.ExpiresAt {
		fmt.Printf("Token %s has expired. Deleting...\n", latestFile)
		_ = os.Remove(tokenPath)
		return
	}

	// Step 4: Call chaincode for validation (e.g., blacklisting/revocation)
	result, err := contract.EvaluateTransaction("ValidateToken", string(tokenData))
	if err != nil {
		fmt.Println("Token validation failed on chain:", err)
		return
	}

	// Step 5: Verify signature using main.go's public key
	publicKeyPath := "crypto/public.pem"
	publicKey, err := LoadRSAPublicKeyFromFile(publicKeyPath)
	if err != nil {
		fmt.Println("Failed to load main.go's public key:", err)
		return
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		fmt.Println("Invalid signature encoding.")
		return
	}

	hashed := sha256.Sum256([]byte(signingInput))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println("Signature verification failed. Token is NOT legit.")
		return
	}

	// All checks passed
	fmt.Printf("Token %s is VALID and signature is legit.\n", latestFile)
	fmt.Println("Chaincode validation response:", string(result))
}



// revokeToken - Function to revoke a token by NF ID
func revokeToken(contract *client.Contract, nfID string) error {
	// Use SubmitTransaction to invoke the RevokeToken function
	_, err := contract.SubmitTransaction("RevokeToken", nfID)
	if err != nil {
		return fmt.Errorf("error invoking RevokeToken: %v", err)
	}

	// Define the file path of the token to be revoked
	tokenFilePath := filepath.Join("../tokens", nfID+".json")

	// Attempt to remove the JSON file storing the token
	err = os.Remove(tokenFilePath)
	if err != nil {
		return fmt.Errorf("failed to delete token file %s: %v", tokenFilePath, err)
	}

	// Success message
	fmt.Println("Token revoked successfully and file deleted.")
	return nil
}



func LoadRSAPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

func LoadRSAPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}














// func printJWTTable(header string, payloadEncoded string, payloadJSON []byte, sigEncoded string) {
// 	fmt.Println("+------------+------------------------------------------------------------------+")
// 	fmt.Println("| Section    | Value                                                            |")
// 	fmt.Println("+------------+------------------------------------------------------------------+")

// 	fmt.Printf("| Header     | %s\n", header)
// 	fmt.Printf("|            | %s\n", `{"alg":"RS256","typ":"JWT"}`)
// 	fmt.Println("+------------+------------------------------------------------------------------+")

// 	fmt.Printf("| Payload    | %s\n", payloadEncoded)

// 	// Split payload JSON into lines of max 66 chars for better formatting
// 	payloadLines := splitIntoChunks(string(payloadJSON), 66)
// 	for _, line := range payloadLines {
// 		fmt.Printf("|            | %s\n", line)
// 	}
// 	fmt.Println("+------------+------------------------------------------------------------------+")

// 	// Signature (also might be very long)
// 	sigLines := splitIntoChunks(sigEncoded, 66)
// 	fmt.Printf("| Signature  | %s\n", sigLines[0])
// 	for _, line := range sigLines[1:] {
// 		fmt.Printf("|            | %s\n", line)
// 	}
// 	fmt.Println("+------------+------------------------------------------------------------------+")
// }

// func splitIntoChunks(s string, chunkSize int) []string {
// 	var chunks []string
// 	for len(s) > chunkSize {
// 		chunks = append(chunks, s[:chunkSize])
// 		s = s[chunkSize:]
// 	}
// 	chunks = append(chunks, s)
// 	return chunks
// }
