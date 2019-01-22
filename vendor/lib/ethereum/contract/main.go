package contract

import (
  "log"
  "github.com/ethereum/go-ethereum/common"
  "github.com/ethereum/go-ethereum/ethclient"
  "github.com/ethereum/go-ethereum/node"
  logGeth "github.com/ethereum/go-ethereum/log"
)

// Smart contract addresses
const (
	AccessRightsAddress = 		"0x0731e5a967e246131cee545729dfe79208032922"
	OwnershipAddress = 				"0x6bf1aeaf4ac69aeb4d0b1622cc28fe3fe4caca75"
	ProofOfExistenceAddress = "0xc5242616437af5acbf4a48bc7482400608498cb1"
	ProofOfTransferAddress = 	"0x0f0805a3d220c232f692a2dfea022f1e3172c77b"
	RegisterIDAddress = 			"0xe12163177b4d7ac9acdb505658802a34de21534c"
)

// Delare the instance of each contract as global variables
var InstAccessRights      *AccessRights
var InstOwnership         *Ownership
var InstProofOfExistence  *ProofOfExistence
var InstProofOfTransfer   *ProofOfTransfer
var InstRegisterID        *RegisterID

func InitContracts() {
  // Create an IPC based RPC connection to the geth.ipc
	conn, err := ethclient.Dial(node.PathGethIPC)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

  // Create the instance of each contract
  InstAccessRights, err := NewAccessRights(common.HexToAddress(AccessRightsAddress), conn)
	if err != nil {
		log.Fatalf("Failed to instantiate a AccessRights contract: %v", err)
	}
  InstOwnership, err := NewOwnership(common.HexToAddress(OwnershipAddress), conn)
	if err != nil {
		log.Fatalf("Failed to instantiate a Ownership contract: %v", err)
	}
  InstProofOfExistence, err := NewProofOfExistence(common.HexToAddress(ProofOfExistenceAddress), conn)
	if err != nil {
		log.Fatalf("Failed to instantiate a ProofOfExistence contract: %v", err)
	}
  InstProofOfTransfer, err := NewProofOfTransfer(common.HexToAddress(ProofOfTransferAddress), conn)
	if err != nil {
		log.Fatalf("Failed to instantiate a ProofOfTransfer contract: %v", err)
	}
  InstRegisterID, err := NewRegisterID(common.HexToAddress(RegisterIDAddress), conn)
	if err != nil {
		log.Fatalf("Failed to instantiate a RegisterID contract: %v", err)
	}

  logGeth.Info("Contract instance for InstAccessRights:", InstAccessRights)
  logGeth.Info("Contract instance for InstOwnership:", InstOwnership)
  logGeth.Info("Contract instance for InstProofOfExistence:", InstProofOfExistence)
  logGeth.Info("Contract instance for InstProofOfTransfer:", InstProofOfTransfer)
  logGeth.Info("Contract instance for InstRegisterID:", InstRegisterID)

}
