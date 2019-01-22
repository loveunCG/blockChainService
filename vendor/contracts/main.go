package main

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	// Create an IPC based RPC connection to a remote node 
	conn, err := ethclient.Dial("/home/sjehan/dappbox/node0/geth.ipc")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	// Instantiate the contract with the deployed @ and display its owner
	proof, err := NewProofOfExistence(common.HexToAddress("0x442dce6a1370ceee9eea2402359a1c36804fc86f"), conn)
	if err != nil {
		log.Fatalf("Failed to instantiate a ProofOfExistence contract: %v", err)
	}
	owner, err := proof.Owner(nil)
	if err != nil {
		log.Fatalf("Failed to retrieve ProofOfExistence owner: %v", err)
	}
	fmt.Println("Contract owner:", owner)
}
