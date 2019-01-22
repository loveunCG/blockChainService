// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package main

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// ProofOfTransferABI is the input ABI used to generate the binding from.
const ProofOfTransferABI = "[{\"constant\":true,\"inputs\":[{\"name\":\"hashfile\",\"type\":\"bytes32\"}],\"name\":\"getProof\",\"outputs\":[{\"name\":\"sender\",\"type\":\"address\"},{\"name\":\"receiver\",\"type\":\"address\"},{\"name\":\"timestamp\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"proofs\",\"outputs\":[{\"name\":\"sender\",\"type\":\"address\"},{\"name\":\"receiver\",\"type\":\"address\"},{\"name\":\"hashfile\",\"type\":\"bytes32\"},{\"name\":\"timestamp\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"sender\",\"type\":\"address\"},{\"name\":\"receiver\",\"type\":\"address\"},{\"name\":\"hashfile\",\"type\":\"bytes32\"}],\"name\":\"addProof\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

// ProofOfTransferBin is the compiled bytecode used for deploying new contracts.
const ProofOfTransferBin = `0x6060604052341561000f57600080fd5b5b60018054600160a060020a03191633600160a060020a03161790555b5b6102b68061003c6000396000f300606060405263ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416631b80bb3a811461005e578063444d95b0146100a15780638da5cb5b146100ec5780639d2517171461011b575b600080fd5b341561006957600080fd5b610074600435610157565b604051600160a060020a039384168152919092166020820152604080820192909252606001905180910390f35b34156100ac57600080fd5b6100b760043561018a565b604051600160a060020a0394851681529290931660208301526040808301919091526060820192909252608001905180910390f35b34156100f757600080fd5b6100ff6101be565b604051600160a060020a03909116815260200160405180910390f35b341561012657600080fd5b610143600160a060020a03600435811690602435166044356101cd565b604051901515815260200160405180910390f35b600081815260208190526040902080546001820154600390920154600160a060020a0391821692909116905b9193909250565b6000602081905290815260409020805460018201546002830154600390930154600160a060020a0392831693919092169184565b600154600160a060020a031681565b600060806040519081016040908152600160a060020a0380871683528516602080840191909152818301859052426060840152600085815290819052208151815473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a0391909116178155602082015160018201805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a039290921691909117905560408201516002820155606082015160039091015550600190505b93925050505600a165627a7a723058209a6345bdfc011b15dbb9f43d807756c7e7e5620a515a60087461681413f220820029`

// DeployProofOfTransfer deploys a new Ethereum contract, binding an instance of ProofOfTransfer to it.
func DeployProofOfTransfer(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *ProofOfTransfer, error) {
	parsed, err := abi.JSON(strings.NewReader(ProofOfTransferABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(ProofOfTransferBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ProofOfTransfer{ProofOfTransferCaller: ProofOfTransferCaller{contract: contract}, ProofOfTransferTransactor: ProofOfTransferTransactor{contract: contract}}, nil
}

// ProofOfTransfer is an auto generated Go binding around an Ethereum contract.
type ProofOfTransfer struct {
	ProofOfTransferCaller     // Read-only binding to the contract
	ProofOfTransferTransactor // Write-only binding to the contract
}

// ProofOfTransferCaller is an auto generated read-only Go binding around an Ethereum contract.
type ProofOfTransferCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ProofOfTransferTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ProofOfTransferTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ProofOfTransferSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ProofOfTransferSession struct {
	Contract     *ProofOfTransfer  // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ProofOfTransferCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ProofOfTransferCallerSession struct {
	Contract *ProofOfTransferCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts          // Call options to use throughout this session
}

// ProofOfTransferTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ProofOfTransferTransactorSession struct {
	Contract     *ProofOfTransferTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts          // Transaction auth options to use throughout this session
}

// ProofOfTransferRaw is an auto generated low-level Go binding around an Ethereum contract.
type ProofOfTransferRaw struct {
	Contract *ProofOfTransfer // Generic contract binding to access the raw methods on
}

// ProofOfTransferCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ProofOfTransferCallerRaw struct {
	Contract *ProofOfTransferCaller // Generic read-only contract binding to access the raw methods on
}

// ProofOfTransferTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ProofOfTransferTransactorRaw struct {
	Contract *ProofOfTransferTransactor // Generic write-only contract binding to access the raw methods on
}

// NewProofOfTransfer creates a new instance of ProofOfTransfer, bound to a specific deployed contract.
func NewProofOfTransfer(address common.Address, backend bind.ContractBackend) (*ProofOfTransfer, error) {
	contract, err := bindProofOfTransfer(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ProofOfTransfer{ProofOfTransferCaller: ProofOfTransferCaller{contract: contract}, ProofOfTransferTransactor: ProofOfTransferTransactor{contract: contract}}, nil
}

// NewProofOfTransferCaller creates a new read-only instance of ProofOfTransfer, bound to a specific deployed contract.
func NewProofOfTransferCaller(address common.Address, caller bind.ContractCaller) (*ProofOfTransferCaller, error) {
	contract, err := bindProofOfTransfer(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &ProofOfTransferCaller{contract: contract}, nil
}

// NewProofOfTransferTransactor creates a new write-only instance of ProofOfTransfer, bound to a specific deployed contract.
func NewProofOfTransferTransactor(address common.Address, transactor bind.ContractTransactor) (*ProofOfTransferTransactor, error) {
	contract, err := bindProofOfTransfer(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &ProofOfTransferTransactor{contract: contract}, nil
}

// bindProofOfTransfer binds a generic wrapper to an already deployed contract.
func bindProofOfTransfer(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ProofOfTransferABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ProofOfTransfer *ProofOfTransferRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _ProofOfTransfer.Contract.ProofOfTransferCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ProofOfTransfer *ProofOfTransferRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ProofOfTransfer.Contract.ProofOfTransferTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ProofOfTransfer *ProofOfTransferRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ProofOfTransfer.Contract.ProofOfTransferTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ProofOfTransfer *ProofOfTransferCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _ProofOfTransfer.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ProofOfTransfer *ProofOfTransferTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ProofOfTransfer.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ProofOfTransfer *ProofOfTransferTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ProofOfTransfer.Contract.contract.Transact(opts, method, params...)
}

// GetProof is a free data retrieval call binding the contract method 0x1b80bb3a.
//
// Solidity: function getProof(hashfile bytes32) constant returns(sender address, receiver address, timestamp uint256)
func (_ProofOfTransfer *ProofOfTransferCaller) GetProof(opts *bind.CallOpts, hashfile [32]byte) (struct {
	Sender    common.Address
	Receiver  common.Address
	Timestamp *big.Int
}, error) {
	ret := new(struct {
		Sender    common.Address
		Receiver  common.Address
		Timestamp *big.Int
	})
	out := ret
	err := _ProofOfTransfer.contract.Call(opts, out, "getProof", hashfile)
	return *ret, err
}

// GetProof is a free data retrieval call binding the contract method 0x1b80bb3a.
//
// Solidity: function getProof(hashfile bytes32) constant returns(sender address, receiver address, timestamp uint256)
func (_ProofOfTransfer *ProofOfTransferSession) GetProof(hashfile [32]byte) (struct {
	Sender    common.Address
	Receiver  common.Address
	Timestamp *big.Int
}, error) {
	return _ProofOfTransfer.Contract.GetProof(&_ProofOfTransfer.CallOpts, hashfile)
}

// GetProof is a free data retrieval call binding the contract method 0x1b80bb3a.
//
// Solidity: function getProof(hashfile bytes32) constant returns(sender address, receiver address, timestamp uint256)
func (_ProofOfTransfer *ProofOfTransferCallerSession) GetProof(hashfile [32]byte) (struct {
	Sender    common.Address
	Receiver  common.Address
	Timestamp *big.Int
}, error) {
	return _ProofOfTransfer.Contract.GetProof(&_ProofOfTransfer.CallOpts, hashfile)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_ProofOfTransfer *ProofOfTransferCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _ProofOfTransfer.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_ProofOfTransfer *ProofOfTransferSession) Owner() (common.Address, error) {
	return _ProofOfTransfer.Contract.Owner(&_ProofOfTransfer.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_ProofOfTransfer *ProofOfTransferCallerSession) Owner() (common.Address, error) {
	return _ProofOfTransfer.Contract.Owner(&_ProofOfTransfer.CallOpts)
}

// Proofs is a free data retrieval call binding the contract method 0x444d95b0.
//
// Solidity: function proofs( bytes32) constant returns(sender address, receiver address, hashfile bytes32, timestamp uint256)
func (_ProofOfTransfer *ProofOfTransferCaller) Proofs(opts *bind.CallOpts, arg0 [32]byte) (struct {
	Sender    common.Address
	Receiver  common.Address
	Hashfile  [32]byte
	Timestamp *big.Int
}, error) {
	ret := new(struct {
		Sender    common.Address
		Receiver  common.Address
		Hashfile  [32]byte
		Timestamp *big.Int
	})
	out := ret
	err := _ProofOfTransfer.contract.Call(opts, out, "proofs", arg0)
	return *ret, err
}

// Proofs is a free data retrieval call binding the contract method 0x444d95b0.
//
// Solidity: function proofs( bytes32) constant returns(sender address, receiver address, hashfile bytes32, timestamp uint256)
func (_ProofOfTransfer *ProofOfTransferSession) Proofs(arg0 [32]byte) (struct {
	Sender    common.Address
	Receiver  common.Address
	Hashfile  [32]byte
	Timestamp *big.Int
}, error) {
	return _ProofOfTransfer.Contract.Proofs(&_ProofOfTransfer.CallOpts, arg0)
}

// Proofs is a free data retrieval call binding the contract method 0x444d95b0.
//
// Solidity: function proofs( bytes32) constant returns(sender address, receiver address, hashfile bytes32, timestamp uint256)
func (_ProofOfTransfer *ProofOfTransferCallerSession) Proofs(arg0 [32]byte) (struct {
	Sender    common.Address
	Receiver  common.Address
	Hashfile  [32]byte
	Timestamp *big.Int
}, error) {
	return _ProofOfTransfer.Contract.Proofs(&_ProofOfTransfer.CallOpts, arg0)
}

// AddProof is a paid mutator transaction binding the contract method 0x9d251717.
//
// Solidity: function addProof(sender address, receiver address, hashfile bytes32) returns(success bool)
func (_ProofOfTransfer *ProofOfTransferTransactor) AddProof(opts *bind.TransactOpts, sender common.Address, receiver common.Address, hashfile [32]byte) (*types.Transaction, error) {
	return _ProofOfTransfer.contract.Transact(opts, "addProof", sender, receiver, hashfile)
}

// AddProof is a paid mutator transaction binding the contract method 0x9d251717.
//
// Solidity: function addProof(sender address, receiver address, hashfile bytes32) returns(success bool)
func (_ProofOfTransfer *ProofOfTransferSession) AddProof(sender common.Address, receiver common.Address, hashfile [32]byte) (*types.Transaction, error) {
	return _ProofOfTransfer.Contract.AddProof(&_ProofOfTransfer.TransactOpts, sender, receiver, hashfile)
}

// AddProof is a paid mutator transaction binding the contract method 0x9d251717.
//
// Solidity: function addProof(sender address, receiver address, hashfile bytes32) returns(success bool)
func (_ProofOfTransfer *ProofOfTransferTransactorSession) AddProof(sender common.Address, receiver common.Address, hashfile [32]byte) (*types.Transaction, error) {
	return _ProofOfTransfer.Contract.AddProof(&_ProofOfTransfer.TransactOpts, sender, receiver, hashfile)
}
