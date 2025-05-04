
# Decentralized OAuth 2.0 Token Issuer for Simulated Network Functions (NFs)
### (A step by step guide to my task)

----
## Prerequisites

| PreReqs | Cmd/Links |
| ------ | ------ |
| git | `sudo apt-get install git` |
| Docker | Refer to Docker documentation for installation on your OS. Ensure Docker Engine and Docker Compose are installed. |
| cURL | `sudo apt-get install curl` |
| go | [https://go.dev/doc/install] (Ensure your `GOPATH` and `PATH` are correctly configured) |
| Hyperledger Fabric Binaries & Docker Images | Follow the instructions below to download |

Do ensure the prerequisites are installed and that the Docker daemon is running:
```bash
sudo systemctl start docker
```

Refer to the [Hyperledger Fabric documentation](https://hyperledger-fabric.readthedocs.io/en/release-2.5/install.html) if you encounter any issues installing Fabric prerequisites.

## Download Fabric samples, Docker images, and binaries

It is recommended to work within your Go workspace directory, typically `$HOME/go/src/github.com/<your_github_userid>`.

#### Cloning the project repository and downloading Fabric binaries

First, navigate to your Go source directory:
```bash
cd $HOME/go/src/[github.com/](https://github.com/)<your_github_userid>
```

Then, clone your project repository and download the Fabric installation script:
```bash
git clone [https://github.com/Rudrakshrawal/task](https://github.com/Rudrakshrawal/task)
cd task
curl -sSLO [https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh](https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh) && chmod +x install-fabric.sh
```
> Installing the Fabric Docker images and platform-specific binaries now:
```bash
./install-fabric.sh docker samples binary
# or the shorthand:
./install-fabric.sh d s b
```

**Note:** This script will download the Fabric binaries and Docker images for the latest stable release. If you need a specific version, you might need to adjust the script or follow the manual installation steps in the Fabric documentation.

## Setting up the Fabric Network

This guide uses the basic `test-network` provided by Hyperledger Fabric.

1.  **Navigate to the `test-network` directory:**
    ```bash
    cd fabric-samples/test-network
    ```

2.  **Bring up the Fabric network:**
    ```bash
    ./network.sh up createChannel -c mychannel -ca -s couchdb  
    ```
    This command creates a Fabric network with one organization, two peers, and an orderer along with a couchdb db.

## Interacting with the network

Make sure that you are operating from the test-network directory. If you followed the instructions to install the Samples, Binaries and Docker Images, You can find the peer binaries in the bin folder of the fabric-samples repository.

```
#Use the following command to add those binaries to your CLI Path:

export PATH=${PWD}/../bin:$PATH
#You also need to set the FABRIC_CFG_PATH to point to the core.yaml file in the fabric-samples repository:

export FABRIC_CFG_PATH=$PWD/../config/
#You can now set the environment variables that allow you to operate the peer CLI as Org1:

# Environment variables for Org1

export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
The CORE_PEER_TLS_ROOTCERT_FILE and CORE_PEER_MSPCONFIGPATH environment variables point to the Org1 crypto material in the organizations folder.
```

## Deploying the chaincode

Use the following command to install chaincode to each pair. 
```
./network.sh deployCC -ccn contract -ccp ../../chaincode  -ccl go
```
After the deployment of the chaincode we will use the ```InitLedger``` function to initialise the Bearer and its public key.
```
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n contract --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" -c '{"function":"InitLedger","Args":[]}'
```
 
 A successful invoke will show ``` INFO [chaincodeCmd] chaincodeInvokeOrQuery -> Chaincode invoke successful. result: status:200  ``` .
## Interacting with the chaincode

Head back to the root directory where your ```<your_github_userid>``` is and ensure that after cloning this repo you find ```chaincode ,gw, nfs ``` directory herein.

Now head to ```gw``` directory where you'll find ```function.go , main.go,``` and ```gateway.go``` and use the following commands to import and initialise your project.
```
go mod init
go mod tidy
go mod vendor
```




## Running the Application

Now run the main file using ```go run . ```
After that you'll enter in a loop where you'll interact with the chaincode.

``` Select task (register / issue / validate / list / revoke / exit): ```

Before proceeding a look at the structure of the directories .

## Playing with Functions
### Register
To register the NF
``` 
register
../nfs/nf4
```

will show an output.
``` 
NF registered successfully with public key.
Field                       Value
-----                       -----
priority                    1
load                        20
nfInstanceId                smf-999
nfStatus                    REGISTERED
allowedNfTypes              [AMF UDM]
capacity                    100
nfServices                  []
nfProfileChangesSupportInd  true
nfType                      SMF
ipv4Addresses               [10.0.0.4]         
```
register atleast 2 NFs
### Issue ,validate and revoke
```
Select task (register / issue / validate / list / revoke / exit): issue
Please enter the path to the NF for which you want to issue the token: ../nfs/nf1
Enter target NF type to request access to: SMF
Token saved as ../nfs/nf1/tokens/jwt1.json
Token issued and signed by bearer .

Select task (register / issue / validate / list / revoke / exit): validate
Please enter the path to the NF where the token is stored: ../nfs/nf1
Token jwt1.json is VALID and signature is legit.
Chaincode validation response: true

Select task (register / issue / validate / list / revoke / exit): revoke
Please enter the NF ID that issued the token: amf-123
Please enter the exact token value to revoke: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuZkluc3RhbmNlSWQiOiJhbWYtMTIzIiwiaWF0IjoxNzQ2MzgwNjE1LCJleHAiOjE3NDYzODA5MTUsImlzcyI6IkJlYXJlciIsImF1ZCI6InNtZi00NTYifQ==.Ob2ohUPUl/86CqF31m/Xg3c43yPcspSgkjpVXjiH02L2mgdWAGtqfvlvA6MftLo+UZZTLMqRQVN8z2D5pWCS/M/zX/dR3cMdR8OkTAXZUthiPmYGogMFKNttFSagkfJVWSN7yOn8Spv+qp5+ndwhEVIK7WpiJppZUQZk4WhfrrjN0K5qITpa9IfqZ0tki5N8wVlYn2SbNA8okrku/Yr7PKZgwJkIKUqJsR0Zbc1+7B41zUFHCHwdzPe2+/QcdnBnoYFtFIT8KBUZu2M6yeuvPoj3CQmhsxMQd4OHyP8xxytT5+Cfp/PF6eGEZPw3GTJ3SJfGI7t4wCo+37g0NMHlfw==
Warning: NF with ID 'amf-123' not found in '../nfs'.
Token revoked on blockchain, but local file cannot be located. 

Select task (register / issue / validate / list / revoke / exit): exit
 Exiting program ...
```


The error showing ```Token revoked on blockchain, but local file cannot be located. ```
means  the revocation process is completed but the naming scheme doesn't match with the NF id.
Will be fixed.

