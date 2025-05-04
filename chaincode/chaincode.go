package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)


const(

)


type SmartContract struct {
	contractapi.Contract
}

type AssociatedToken struct {
	Token     string `json:"token"`
	Audience  string `json:"audience"` // The NF this token is intended for
	ExpiresAt int64  `json:"expiresAt"`
}

type NFProfile struct {
	NFInstanceID        string       `json:"nfInstanceId"`
	NFType              string       `json:"nfType"`
	NFStatus            string       `json:"nfStatus"`
	IPv4Addresses       []string     `json:"ipv4Addresses"`
	AllowedNfTypes      []string     `json:"allowedNfTypes"`
	Priority            int          `json:"priority"`
	Capacity            int          `json:"capacity"`
	Load                int          `json:"load"`
	NFServices          []NFService  `json:"nfServices"`
	ChangesSupport      bool         `json:"nfProfileChangesSupportInd"`
}

type NFService struct {
	ServiceInstanceID string       `json:"serviceInstanceId"`
	ServiceName       string       `json:"serviceName"`
	Versions          []NFVersion  `json:"versions"`
	Scheme            string       `json:"scheme"`
	NFServiceStatus   string       `json:"nfServiceStatus"`
	IPEndPoints       []IPEndPoint `json:"ipEndPoints"`
	AllowedNfTypes    []string     `json:"allowedNfTypes"`
	Priority          int          `json:"priority"`
	Capacity          int          `json:"capacity"`
	Load              int          `json:"load"`
}

type NFVersion struct {
	APIVersionURI  string `json:"apiVersionInUri"`
	APIFullVersion string `json:"apiFullVersion"`
}

type IPEndPoint struct {
	IPv4Address string `json:"ipv4Address"`
	Port        int    `json:"port"`
}

type TokenPayload struct {
	NFInstanceID string `json:"nfInstanceId"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
	IssuerID   string `json:"iss"`  // Issuer ID
	AudienceID string `json:"aud"`
}
//for the public keys
type NFRecord struct {
	Profile    NFProfile `json:"profile"`
	PublicKey  string    `json:"publicKey"` //PEM string
	NFInstanceID string `json:"nfInstanceId"`
	NFType       string `json:"nfType"`
}


func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	// Check if Bearer is already registered
	bearerID := "Bearer"
	existing, err := ctx.GetStub().GetState(bearerID)
	if err != nil {
		return fmt.Errorf("failed to check existing NF: %v", err)
	}
	if existing != nil {
		return nil // Already registered, skip
	}

	// Construct the full NF profile
	bearerProfile := NFProfile{
		NFInstanceID:   bearerID,
		NFType:         "Bearer",
		NFStatus:       "REGISTERED",
		IPv4Addresses:  []string{"127.0.0.1"},
		AllowedNfTypes: []string{}, // Adjust as needed
		Priority:       1,
		Capacity:       100,
		Load:           0,
		NFServices:     []NFService{},
		ChangesSupport: false,
	}

	bearerNF := NFRecord{
		Profile: bearerProfile,
		PublicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO/mxWNKEdlr7saRIW50
/4tT8ic4MG3CiarhlrF1TWpOFr7lSiXS2pgHRrGMKGoyI+CTqXTbGGynSeO/ilm2
UDP5r8hy1kPEr3vgnu4zTzfn78oQwHEPWbMcIE+x0zWkCOWaNlTrAMZhGuXkSRu1
juM0oGE3pD5O/oRNO3Yfnc1DB3P9FPhgrMmYVag86f/sDxmnd3cNqETBPAEcjFvC
sBgW7cnxlQbBlxb+sSIiV5/rRDxI82gHAXsF49xVJtbz1EuimEUFqfeQ7E2VGb9n
wFRiRlYdz9O3FLx1eT3Lk8vJ1t9c6+csZVXrEiPSnCaxHP9D2iiKwxYUtlx2TZZ2
rQIDAQAB
-----END PUBLIC KEY-----`,
		NFInstanceID: bearerProfile.NFInstanceID,
		NFType:       bearerProfile.NFType,
	}

	bearerBytes, err := json.Marshal(bearerNF)
	if err != nil {
		return fmt.Errorf("failed to marshal bearer NF: %v", err)
	}
	show := ctx.GetStub().PutState(bearerID, bearerBytes)
	// fmt.Printf(bearerID)
	return show
}








func (s *SmartContract) RegisterNF(ctx contractapi.TransactionContextInterface, nfID string, nfProfileJSON string, publicKeyPEM string) error {
	var nfProfile NFProfile
	if err := json.Unmarshal([]byte(nfProfileJSON), &nfProfile); err != nil {
		return fmt.Errorf("failed to parse NF profile: %v", err)
	}
//stores the public key too
	nfRecord := NFRecord{
		Profile:   nfProfile,
		PublicKey: publicKeyPEM,
	}
	data, err := json.Marshal(nfRecord)//marshals the record
	if err != nil {
		return fmt.Errorf("failed to serialize NF record: %v", err)
	}
	return ctx.GetStub().PutState(nfID, data)
}




//to register bearer's (main.go's) pub key
func (s *SmartContract) RegisterClientPubKey(ctx contractapi.TransactionContextInterface, clientID string, pubKeyPEM string) error {
	if clientID == "" || pubKeyPEM == "" {
		return fmt.Errorf("client ID and public key must be provided")
	}
	return ctx.GetStub().PutState("CLIENTPUB_"+clientID, []byte(pubKeyPEM))
}
//to retrieve it 
func (s *SmartContract) GetClientPubKey(ctx contractapi.TransactionContextInterface, clientID string) (string, error) {
	pubKeyBytes, err := ctx.GetStub().GetState("CLIENTPUB_" + clientID)
	if err != nil {
		return "", fmt.Errorf("failed to read client pub key from ledger: %v", err)
	}
	if pubKeyBytes == nil {
		return "", fmt.Errorf("public key for client '%s' not found", clientID)
	}
	return string(pubKeyBytes), nil
}







func (s *SmartContract) ValidateToken(ctx contractapi.TransactionContextInterface, token string) (bool, error) {
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return false, errors.New("invalid token format")
    }

    payloadJSON, _ := base64.StdEncoding.DecodeString(parts[1])
    var payload TokenPayload
    if err := json.Unmarshal(payloadJSON, &payload); err != nil {
        return false, err
    }

    if payload.ExpiresAt < time.Now().Unix() {
        return false, errors.New("token expired")
    }

    nfID := payload.IssuerID // or AudienceID depending on your logic
    nfRecordBytes, err := ctx.GetStub().GetState(nfID)
    if err != nil || nfRecordBytes == nil {
        return false, fmt.Errorf("NF record not found for ID: %s", nfID)
    }

    var nfRecord NFRecord
    if err := json.Unmarshal(nfRecordBytes, &nfRecord); err != nil {
        return false, fmt.Errorf("failed to parse NF record: %v", err)
    }

    block, _ := pem.Decode([]byte(nfRecord.PublicKey))
    if block == nil || block.Type != "PUBLIC KEY" {
        return false, errors.New("invalid public key format in ledger")
    }

    pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return false, err
    }
    publicKey := pubInterface.(*rsa.PublicKey)

    signingInput := fmt.Sprintf("%s.%s", parts[0], parts[1])
    hashed := sha256.Sum256([]byte(signingInput))
    sig, err := base64.StdEncoding.DecodeString(parts[2])
    if err != nil {
        return false, err
    }

    err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], sig)
    return err == nil, err
}





func (s *SmartContract) ShowAllNFs(ctx contractapi.TransactionContextInterface) (string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return "", fmt.Errorf("failed to get state by range: %v", err)
	}
	defer resultsIterator.Close()

	type NFWithTokens struct {
		NFInstanceID string            `json:"nfInstanceId"`
		NFType       string            `json:"nfType"`
		Tokens       []AssociatedToken `json:"tokens,omitempty"`
	}

	nfMap := make(map[string]*NFWithTokens)

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return "", err
		}

		key := queryResponse.Key
		value := queryResponse.Value

		if strings.HasPrefix(key, "NF_TOKEN::") {
			parts := strings.Split(key, "::")
			if len(parts) == 3 {
				issuerNFID := parts[1]
				tokenBytes := value
				var associatedToken AssociatedToken
				if err := json.Unmarshal(tokenBytes, &associatedToken); err == nil {
					if nf, exists := nfMap[issuerNFID]; exists {
						nf.Tokens = append(nf.Tokens, associatedToken)
					} else {
						// Create a temporary entry. It will be merged later.
						nfMap[issuerNFID] = &NFWithTokens{
							NFInstanceID: issuerNFID,
							Tokens:       []AssociatedToken{associatedToken},
						}
					}
				}
			}
			continue
		}

		var nfRecord NFRecord
		if err := json.Unmarshal(value, &nfRecord); err == nil {
			if _, exists := nfMap[nfRecord.Profile.NFInstanceID]; !exists {
				nfMap[nfRecord.Profile.NFInstanceID] = &NFWithTokens{
					NFInstanceID: nfRecord.Profile.NFInstanceID,
					NFType:       nfRecord.Profile.NFType,
					Tokens:       []AssociatedToken{}, // Initialize token list
				}
			} else {
				// Ensure NF type is populated if the NF record was processed after a token
				nfMap[nfRecord.Profile.NFInstanceID].NFType = nfRecord.Profile.NFType
			}
		}
	}

	var nfList []NFWithTokens
	for _, nf := range nfMap {
		nfList = append(nfList, *nf)
	}

	nfListJSON, err := json.MarshalIndent(nfList, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal NF list with tokens: %v", err)
	}

	return string(nfListJSON), nil
}



//to show the public id of the nf
func (s *SmartContract) GetNFPubKey(ctx contractapi.TransactionContextInterface, nfID string) (string, error) {
	nfBytes, err := ctx.GetStub().GetState(nfID)
	if err != nil || nfBytes == nil {
		return "", fmt.Errorf("NF not found")
	}
	var nfRecord NFRecord
	if err := json.Unmarshal(nfBytes, &nfRecord); err != nil {
		return "", err
	}
	return nfRecord.PublicKey, nil
}



func (s *SmartContract) UploadToken(ctx contractapi.TransactionContextInterface, nfID string, token string) error {
	// Basic format check
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	// Decode payload to check expiration
	payloadJSON, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode token payload: %v", err)
	}

	var payload TokenPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return fmt.Errorf("invalid token payload: %v", err)
	}

	// // validate the token matches NF ID
	// if payload.AudienceID != nfID {
	// 	return fmt.Errorf("token audience does not match provided NF ID")
	// }

	key := "token::" + nfID
	return ctx.GetStub().PutState(key, []byte(token))
}

func (s *SmartContract) ShowNFToken(ctx contractapi.TransactionContextInterface, nfID string) (string, error) {
	// This function now needs to iterate through all tokens associated with the given NF ID
	resultsIterator, err := ctx.GetStub().GetStateByRange(fmt.Sprintf("NF_TOKEN::%s::", nfID), fmt.Sprintf("NF_TOKEN::%s::\xff", nfID))
	if err != nil {
		return "", fmt.Errorf("failed to get tokens for NF ID %s: %v", nfID, err)
	}
	defer resultsIterator.Close()

	var tokens []AssociatedToken
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return "", err
		}
		var tokenData AssociatedToken
		if err := json.Unmarshal(queryResponse.Value, &tokenData); err == nil {
			if time.Now().Unix() <= tokenData.ExpiresAt {
				tokens = append(tokens, tokenData)
			} else {
				// Optionally delete expired tokens here
				_ = ctx.GetStub().DelState(queryResponse.Key)
			}
		}
	}

	if len(tokens) == 0 {
		return "", fmt.Errorf("no active tokens found for NF ID: %s", nfID)
	}

	resultJSON, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal tokens: %v", err)
	}
	return string(resultJSON), nil
}

func (s *SmartContract) RevokeToken(ctx contractapi.TransactionContextInterface, issuerNFid string, token string) error {
	key := fmt.Sprintf("NF_TOKEN::%s::%s", issuerNFid, token)
	return ctx.GetStub().DelState(key)


}

















func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		fmt.Printf("Error create chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting chaincode: %s", err.Error())
	}
}

// func (s *SmartContract) IssueToken(ctx contractapi.TransactionContextInterface, issuerID, audienceID string) (string, error) {
// 	// Fetch the issuer NF profile from the ledger
// 	issuerProfileBytes, err := ctx.GetStub().GetState(issuerID)
// 	if err != nil || issuerProfileBytes == nil {
// 		return "", fmt.Errorf("issuer NF profile not found for ID: %s", issuerID)
// 	}

// 	// Fetch the audience NF profile from the ledger
// 	audienceProfileBytes, err := ctx.GetStub().GetState(audienceID)
// 	if err != nil || audienceProfileBytes == nil {
// 		return "", fmt.Errorf("audience NF profile not found for ID: %s", audienceID)
// 	}

// 	// Prepare the JWT header and payload
// 	header := base64.StdEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

// 	// Define the token payload
// 	payload := TokenPayload{
// 		NFInstanceID: issuerID,
// 		IssuerID:   issuerID,
// 		AudienceID: audienceID,
// 		IssuedAt:   time.Now().Unix(),
// 		ExpiresAt:  time.Now().Add(10 * time.Minute).Unix(),
// 	}
// 	fmt.Printf("Attempting to issue token from %s to %s\n", issuerID, audienceID)
// 	// Marshal the payload to JSON
// 	payloadJSON, err := json.Marshal(payload)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to marshal payload: %v", err)
// 	}

// 	// Base64 encode the payload
// 	payloadEncoded := base64.StdEncoding.EncodeToString(payloadJSON)

// 	// Prepare the signing input
// 	signingInput := fmt.Sprintf("%s.%s", header, payloadEncoded)

// 	// Load the RSA private key for signing
// 	privateKey, err := LoadRSAPrivateKeyFromFile("crypto/private.pem")
// 	if err != nil {
// 		return "", fmt.Errorf("failed to load private key: %v", err)
// 	}

// 	// Hash the signing input and generate the signature
// 	hashed := sha256.Sum256([]byte(signingInput))
// 	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed[:])
// 	if err != nil {
// 		return "", fmt.Errorf("failed to sign JWT: %v", err)
// 	}

// 	// Base64 encode the signature
// 	sigEncoded := base64.StdEncoding.EncodeToString(signature)

// 	// Combine header, payload, and signature to create the full token
// 	token := fmt.Sprintf("%s.%s", signingInput, sigEncoded)

// 	// Store the token in the ledger
// 	err = ctx.GetStub().PutState("token::"+issuerID+"::"+audienceID, []byte(token))
// 	if err != nil {
// 		return "", fmt.Errorf("failed to store token in ledger: %v", err)
// 	}

// 	// Print the JWT sections for debugging
// 	fmt.Println("+------------+------------------------------------------------------------------+")
// 	fmt.Println("+------------+------------------------------------------------------------------+")
// 	fmt.Println("| Section    | Value                                                            |")
// 	fmt.Println("+------------+------------------------------------------------------------------+")
// 	fmt.Printf("| Header     | %s\n", header)
// 	fmt.Printf("|            | %s\n", `{"alg":"RS256","typ":"JWT"}`)
// 	fmt.Println("+------------+------------------------------------------------------------------+")
// 	fmt.Printf("| Payload    | %s\n", payloadEncoded)
// 	fmt.Printf("|            | %s\n", string(payloadJSON))
// 	fmt.Println("+------------+------------------------------------------------------------------+")
// 	fmt.Printf("| Signature  | %s\n", sigEncoded)
// 	fmt.Println("+------------+------------------------------------------------------------------+")
// 	fmt.Println("+------------+------------------------------------------------------------------+")

// 	// Return the generated token
// 	return token, nil
// }