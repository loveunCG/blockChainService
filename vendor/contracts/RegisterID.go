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

// RegisterIDABI is the input ABI used to generate the binding from.
const RegisterIDABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\"}],\"name\":\"register\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"_owner\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_id\",\"type\":\"uint256\"}],\"name\":\"Register\",\"type\":\"event\"}]"

// RegisterIDBin is the compiled bytecode used for deploying new contracts.
const RegisterIDBin = `0x6060604052341561000f57600080fd5b5b60ca8061001e6000396000f300606060405263ffffffff7c0100000000000000000000000000000000000000000000000000000000600035041663f207564e8114603c575b600080fd5b3415604657600080fd5b604f6004356051565b005b3373ffffffffffffffffffffffffffffffffffffffff167e7dc6ab80cc84c043b7b8d4fcafc802187470087f7ea7fccd2e17aecd0256a18260405190815260200160405180910390a25b505600a165627a7a72305820707ae4996708b3ad9fb98c9a08928a3c9e1a0f1f3cc6967e0b8278def8ad79180029`

// DeployRegisterID deploys a new Ethereum contract, binding an instance of RegisterID to it.
func DeployRegisterID(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *RegisterID, error) {
	parsed, err := abi.JSON(strings.NewReader(RegisterIDABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(RegisterIDBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &RegisterID{RegisterIDCaller: RegisterIDCaller{contract: contract}, RegisterIDTransactor: RegisterIDTransactor{contract: contract}}, nil
}

// RegisterID is an auto generated Go binding around an Ethereum contract.
type RegisterID struct {
	RegisterIDCaller     // Read-only binding to the contract
	RegisterIDTransactor // Write-only binding to the contract
}

// RegisterIDCaller is an auto generated read-only Go binding around an Ethereum contract.
type RegisterIDCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegisterIDTransactor is an auto generated write-only Go binding around an Ethereum contract.
type RegisterIDTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegisterIDSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type RegisterIDSession struct {
	Contract     *RegisterID       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// RegisterIDCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type RegisterIDCallerSession struct {
	Contract *RegisterIDCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// RegisterIDTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type RegisterIDTransactorSession struct {
	Contract     *RegisterIDTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// RegisterIDRaw is an auto generated low-level Go binding around an Ethereum contract.
type RegisterIDRaw struct {
	Contract *RegisterID // Generic contract binding to access the raw methods on
}

// RegisterIDCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type RegisterIDCallerRaw struct {
	Contract *RegisterIDCaller // Generic read-only contract binding to access the raw methods on
}

// RegisterIDTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type RegisterIDTransactorRaw struct {
	Contract *RegisterIDTransactor // Generic write-only contract binding to access the raw methods on
}

// NewRegisterID creates a new instance of RegisterID, bound to a specific deployed contract.
func NewRegisterID(address common.Address, backend bind.ContractBackend) (*RegisterID, error) {
	contract, err := bindRegisterID(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &RegisterID{RegisterIDCaller: RegisterIDCaller{contract: contract}, RegisterIDTransactor: RegisterIDTransactor{contract: contract}}, nil
}

// NewRegisterIDCaller creates a new read-only instance of RegisterID, bound to a specific deployed contract.
func NewRegisterIDCaller(address common.Address, caller bind.ContractCaller) (*RegisterIDCaller, error) {
	contract, err := bindRegisterID(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &RegisterIDCaller{contract: contract}, nil
}

// NewRegisterIDTransactor creates a new write-only instance of RegisterID, bound to a specific deployed contract.
func NewRegisterIDTransactor(address common.Address, transactor bind.ContractTransactor) (*RegisterIDTransactor, error) {
	contract, err := bindRegisterID(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &RegisterIDTransactor{contract: contract}, nil
}

// bindRegisterID binds a generic wrapper to an already deployed contract.
func bindRegisterID(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(RegisterIDABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegisterID *RegisterIDRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _RegisterID.Contract.RegisterIDCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegisterID *RegisterIDRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegisterID.Contract.RegisterIDTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegisterID *RegisterIDRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegisterID.Contract.RegisterIDTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegisterID *RegisterIDCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _RegisterID.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegisterID *RegisterIDTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegisterID.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegisterID *RegisterIDTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegisterID.Contract.contract.Transact(opts, method, params...)
}

// Register is a paid mutator transaction binding the contract method 0xf207564e.
//
// Solidity: function register(id uint256) returns()
func (_RegisterID *RegisterIDTransactor) Register(opts *bind.TransactOpts, id *big.Int) (*types.Transaction, error) {
	return _RegisterID.contract.Transact(opts, "register", id)
}

// Register is a paid mutator transaction binding the contract method 0xf207564e.
//
// Solidity: function register(id uint256) returns()
func (_RegisterID *RegisterIDSession) Register(id *big.Int) (*types.Transaction, error) {
	return _RegisterID.Contract.Register(&_RegisterID.TransactOpts, id)
}

// Register is a paid mutator transaction binding the contract method 0xf207564e.
//
// Solidity: function register(id uint256) returns()
func (_RegisterID *RegisterIDTransactorSession) Register(id *big.Int) (*types.Transaction, error) {
	return _RegisterID.Contract.Register(&_RegisterID.TransactOpts, id)
}
