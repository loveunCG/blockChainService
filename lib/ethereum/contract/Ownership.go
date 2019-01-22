// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contract

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// OwnershipABI is the input ABI used to generate the binding from.
const OwnershipABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"ownerfile\",\"type\":\"address\"},{\"name\":\"hashfile\",\"type\":\"bytes32\"}],\"name\":\"addDetails\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\"},{\"name\":\"hashfile\",\"type\":\"bytes32\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"hashfile\",\"type\":\"bytes32\"}],\"name\":\"getDetails\",\"outputs\":[{\"name\":\"timestamp\",\"type\":\"uint256\"},{\"name\":\"ownerfile\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"owners\",\"outputs\":[{\"name\":\"timestamp\",\"type\":\"uint256\"},{\"name\":\"ownerfile\",\"type\":\"address\"},{\"name\":\"hashfile\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

// OwnershipBin is the compiled bytecode used for deploying new contracts.
const OwnershipBin = `0x6060604052341561000f57600080fd5b5b60008054600160a060020a03191633600160a060020a03161790555b5b6102ef8061003c6000396000f300606060405263ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416634c5445c6811461006957806389e6b5fb1461009f5780638da5cb5b146100c3578063984bc700146100f2578063fb8ad6ff14610129575b600080fd5b341561007457600080fd5b61008b600160a060020a036004351660243561016b565b604051901515815260200160405180910390f35b34156100aa57600080fd5b6100c1600160a060020a03600435166024356101f0565b005b34156100ce57600080fd5b6100d6610263565b604051600160a060020a03909116815260200160405180910390f35b34156100fd57600080fd5b610108600435610272565b604051918252600160a060020a031660208201526040908101905180910390f35b341561013457600080fd5b61013f600435610297565b604051928352600160a060020a0390911660208301526040808301919091526060909101905180910390f35b600060606040519081016040908152428252600160a060020a038516602080840191909152818301859052600085815260019091522081518155602082015160018201805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a0392909216919091179055604082015160029091015550600190505b92915050565b60005433600160a060020a0390811691161461020b57600080fd5b600160a060020a038216151561022057600080fd5b6000818152600160208190526040909120908101805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a0385161790554290555b5b5050565b600054600160a060020a031681565b60008181526001602081905260409091208054910154600160a060020a03165b915091565b6001602081905260009182526040909120805491810154600290910154600160a060020a0390911690835600a165627a7a723058204a71b7181482e4e9c78adb3a815190b2a0dec280fbba368703a247b2333c010a0029`

// DeployOwnership deploys a new Ethereum contract, binding an instance of Ownership to it.
func DeployOwnership(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Ownership, error) {
	parsed, err := abi.JSON(strings.NewReader(OwnershipABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(OwnershipBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Ownership{OwnershipCaller: OwnershipCaller{contract: contract}, OwnershipTransactor: OwnershipTransactor{contract: contract}}, nil
}

// Ownership is an auto generated Go binding around an Ethereum contract.
type Ownership struct {
	OwnershipCaller     // Read-only binding to the contract
	OwnershipTransactor // Write-only binding to the contract
}

// OwnershipCaller is an auto generated read-only Go binding around an Ethereum contract.
type OwnershipCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnershipTransactor is an auto generated write-only Go binding around an Ethereum contract.
type OwnershipTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnershipSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type OwnershipSession struct {
	Contract     *Ownership        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// OwnershipCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type OwnershipCallerSession struct {
	Contract *OwnershipCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// OwnershipTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type OwnershipTransactorSession struct {
	Contract     *OwnershipTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// OwnershipRaw is an auto generated low-level Go binding around an Ethereum contract.
type OwnershipRaw struct {
	Contract *Ownership // Generic contract binding to access the raw methods on
}

// OwnershipCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type OwnershipCallerRaw struct {
	Contract *OwnershipCaller // Generic read-only contract binding to access the raw methods on
}

// OwnershipTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type OwnershipTransactorRaw struct {
	Contract *OwnershipTransactor // Generic write-only contract binding to access the raw methods on
}

// NewOwnership creates a new instance of Ownership, bound to a specific deployed contract.
func NewOwnership(address common.Address, backend bind.ContractBackend) (*Ownership, error) {
	contract, err := bindOwnership(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Ownership{OwnershipCaller: OwnershipCaller{contract: contract}, OwnershipTransactor: OwnershipTransactor{contract: contract}}, nil
}

// NewOwnershipCaller creates a new read-only instance of Ownership, bound to a specific deployed contract.
func NewOwnershipCaller(address common.Address, caller bind.ContractCaller) (*OwnershipCaller, error) {
	contract, err := bindOwnership(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &OwnershipCaller{contract: contract}, nil
}

// NewOwnershipTransactor creates a new write-only instance of Ownership, bound to a specific deployed contract.
func NewOwnershipTransactor(address common.Address, transactor bind.ContractTransactor) (*OwnershipTransactor, error) {
	contract, err := bindOwnership(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &OwnershipTransactor{contract: contract}, nil
}

// bindOwnership binds a generic wrapper to an already deployed contract.
func bindOwnership(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(OwnershipABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Ownership *OwnershipRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Ownership.Contract.OwnershipCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Ownership *OwnershipRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Ownership.Contract.OwnershipTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Ownership *OwnershipRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Ownership.Contract.OwnershipTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Ownership *OwnershipCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Ownership.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Ownership *OwnershipTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Ownership.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Ownership *OwnershipTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Ownership.Contract.contract.Transact(opts, method, params...)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_Ownership *OwnershipCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _Ownership.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_Ownership *OwnershipSession) Owner() (common.Address, error) {
	return _Ownership.Contract.Owner(&_Ownership.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_Ownership *OwnershipCallerSession) Owner() (common.Address, error) {
	return _Ownership.Contract.Owner(&_Ownership.CallOpts)
}

// Owners is a free data retrieval call binding the contract method 0xfb8ad6ff.
//
// Solidity: function owners( bytes32) constant returns(timestamp uint256, ownerfile address, hashfile bytes32)
func (_Ownership *OwnershipCaller) Owners(opts *bind.CallOpts, arg0 [32]byte) (struct {
	Timestamp *big.Int
	Ownerfile common.Address
	Hashfile  [32]byte
}, error) {
	ret := new(struct {
		Timestamp *big.Int
		Ownerfile common.Address
		Hashfile  [32]byte
	})
	out := ret
	err := _Ownership.contract.Call(opts, out, "owners", arg0)
	return *ret, err
}

// Owners is a free data retrieval call binding the contract method 0xfb8ad6ff.
//
// Solidity: function owners( bytes32) constant returns(timestamp uint256, ownerfile address, hashfile bytes32)
func (_Ownership *OwnershipSession) Owners(arg0 [32]byte) (struct {
	Timestamp *big.Int
	Ownerfile common.Address
	Hashfile  [32]byte
}, error) {
	return _Ownership.Contract.Owners(&_Ownership.CallOpts, arg0)
}

// Owners is a free data retrieval call binding the contract method 0xfb8ad6ff.
//
// Solidity: function owners( bytes32) constant returns(timestamp uint256, ownerfile address, hashfile bytes32)
func (_Ownership *OwnershipCallerSession) Owners(arg0 [32]byte) (struct {
	Timestamp *big.Int
	Ownerfile common.Address
	Hashfile  [32]byte
}, error) {
	return _Ownership.Contract.Owners(&_Ownership.CallOpts, arg0)
}

// AddDetails is a paid mutator transaction binding the contract method 0x4c5445c6.
//
// Solidity: function addDetails(ownerfile address, hashfile bytes32) returns(success bool)
func (_Ownership *OwnershipTransactor) AddDetails(opts *bind.TransactOpts, ownerfile common.Address, hashfile [32]byte) (*types.Transaction, error) {
	return _Ownership.contract.Transact(opts, "addDetails", ownerfile, hashfile)
}

// AddDetails is a paid mutator transaction binding the contract method 0x4c5445c6.
//
// Solidity: function addDetails(ownerfile address, hashfile bytes32) returns(success bool)
func (_Ownership *OwnershipSession) AddDetails(ownerfile common.Address, hashfile [32]byte) (*types.Transaction, error) {
	return _Ownership.Contract.AddDetails(&_Ownership.TransactOpts, ownerfile, hashfile)
}

// AddDetails is a paid mutator transaction binding the contract method 0x4c5445c6.
//
// Solidity: function addDetails(ownerfile address, hashfile bytes32) returns(success bool)
func (_Ownership *OwnershipTransactorSession) AddDetails(ownerfile common.Address, hashfile [32]byte) (*types.Transaction, error) {
	return _Ownership.Contract.AddDetails(&_Ownership.TransactOpts, ownerfile, hashfile)
}

// GetDetails is a paid mutator transaction binding the contract method 0x984bc700.
//
// Solidity: function getDetails(hashfile bytes32) returns(timestamp uint256, ownerfile address)
func (_Ownership *OwnershipTransactor) GetDetails(opts *bind.TransactOpts, hashfile [32]byte) (*types.Transaction, error) {
	return _Ownership.contract.Transact(opts, "getDetails", hashfile)
}

// GetDetails is a paid mutator transaction binding the contract method 0x984bc700.
//
// Solidity: function getDetails(hashfile bytes32) returns(timestamp uint256, ownerfile address)
func (_Ownership *OwnershipSession) GetDetails(hashfile [32]byte) (*types.Transaction, error) {
	return _Ownership.Contract.GetDetails(&_Ownership.TransactOpts, hashfile)
}

// GetDetails is a paid mutator transaction binding the contract method 0x984bc700.
//
// Solidity: function getDetails(hashfile bytes32) returns(timestamp uint256, ownerfile address)
func (_Ownership *OwnershipTransactorSession) GetDetails(hashfile [32]byte) (*types.Transaction, error) {
	return _Ownership.Contract.GetDetails(&_Ownership.TransactOpts, hashfile)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0x89e6b5fb.
//
// Solidity: function transferOwnership(newOwner address, hashfile bytes32) returns()
func (_Ownership *OwnershipTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address, hashfile [32]byte) (*types.Transaction, error) {
	return _Ownership.contract.Transact(opts, "transferOwnership", newOwner, hashfile)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0x89e6b5fb.
//
// Solidity: function transferOwnership(newOwner address, hashfile bytes32) returns()
func (_Ownership *OwnershipSession) TransferOwnership(newOwner common.Address, hashfile [32]byte) (*types.Transaction, error) {
	return _Ownership.Contract.TransferOwnership(&_Ownership.TransactOpts, newOwner, hashfile)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0x89e6b5fb.
//
// Solidity: function transferOwnership(newOwner address, hashfile bytes32) returns()
func (_Ownership *OwnershipTransactorSession) TransferOwnership(newOwner common.Address, hashfile [32]byte) (*types.Transaction, error) {
	return _Ownership.Contract.TransferOwnership(&_Ownership.TransactOpts, newOwner, hashfile)
}
