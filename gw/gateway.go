/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	mspID        = "Org1MSP"
	cryptoPath   = "../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath     = cryptoPath + "/users/User1@org1.example.com/msp/signcerts"
	keyPath      = cryptoPath + "/users/User1@org1.example.com/msp/keystore"
	tlsCertPath  = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint = "dns:///localhost:7051"
	gatewayPeer  = "peer0.org1.example.com"
)






// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() *grpc.ClientConn {
	certificatePEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		panic(fmt.Errorf("failed to read TLS certifcate file: %w", err))
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM) //Convert the Certificate from PEM Format to X.509 cert
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer) //certificate pool is used for TLS authentication when connecting to the Fabric peer.

	connection, err := grpc.NewClient(peerEndpoint, grpc.WithTransportCredentials(transportCredentials)) //establishes the connection between the client (this program) and Fabric.
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection

  
}





// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity() *identity.X509Identity {
	certificatePEM, err := readFirstFile(certPath) //to read the first certificate file in the given path
	if err != nil {
		panic(fmt.Errorf("failed to read certificate file: %w", err))
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM) //convert the PEM to X.509 format
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate) //creates an identity used to sign the txns
	if err != nil {
		panic(err)
	}

	return id
}






// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
	privateKeyPEM, err := readFirstFile(keyPath) //reads the private key from the keypath
	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM) //converts the path to an usable form
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey) //creates a signing function that generates digital signs
	if err != nil {
		panic(err)
	}

	return sign
} //continued 
func readFirstFile(dirPath string) ([]byte, error) {
	dir, err := os.Open(dirPath) //opens the directory
	if err != nil {
		return nil, err
	}

	fileNames, err := dir.Readdirnames(1) //reads the first anme of the file within the directory 
	if err != nil {
		return nil, err
	}

	return os.ReadFile(path.Join(dirPath, fileNames[0])) //Read the File Contents. Joins dirPath and fileNames[0] to get the full file path.
}




