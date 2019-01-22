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

// ProofOfExistenceABI is the input ABI used to generate the binding from.
const ProofOfExistenceABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"badDevice\",\"type\":\"address\"}],\"name\":\"removeDevice\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"currentDevice\",\"type\":\"address\"},{\"name\":\"currentOperation\",\"type\":\"uint8\"},{\"name\":\"currentFolder\",\"type\":\"string\"},{\"name\":\"currentFilename\",\"type\":\"string\"},{\"name\":\"currentHashfile\",\"type\":\"bytes32\"}],\"name\":\"addChange\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"currentDevice\",\"type\":\"address\"}],\"name\":\"addDevice\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"devices\",\"outputs\":[{\"name\":\"numChanges\",\"type\":\"uint256\"},{\"name\":\"exist\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

// ProofOfExistenceBin is the compiled bytecode used for deploying new contracts.
const ProofOfExistenceBin = `0x6060604052341561000f57600080fd5b5b60018054600160a060020a03191633600160a060020a03161790555b5b61049f8061003c6000396000f300606060405263ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416631f7b632481146100695780633ee540981461009c5780638da5cb5b1461015c578063b111cb841461018b578063e7b4cac6146101be575b600080fd5b341561007457600080fd5b610088600160a060020a03600435166101f7565b604051901515815260200160405180910390f35b34156100a757600080fd5b61008860048035600160a060020a0316906024803560ff16919060649060443590810190830135806020601f8201819004810201604051908101604052818152929190602084018383808284378201915050505050509190803590602001908201803590602001908080601f016020809104026020016040519081016040528181529291906020840183838082843750949650509335935061024592505050565b604051901515815260200160405180910390f35b341561016757600080fd5b61016f610338565b604051600160a060020a03909116815260200160405180910390f35b341561019657600080fd5b610088600160a060020a0360043516610347565b604051901515815260200160405180910390f35b34156101c957600080fd5b6101dd600160a060020a03600435166103b7565b604051918252151560208201526040908101905180910390f35b60015460009033600160a060020a0390811691161461021557600080fd5b50600160a060020a03811660009081526020819052604081209081556001908101805460ff191690555b5b919050565b600160a060020a0385166000908152602081905260408120600181015460ff16151561027057600080fd5b60a06040519081016040528087600281111561028857fe5b815260208082018890526040808301889052606083018790524260809093019290925283546001810185556000908152600285019091522081518154829060ff191660018360028111156102d857fe5b02179055506020820151816001019080516102f79291602001906103d3565b506040820151816002019080516103129291602001906103d3565b5060608201516003820155608082015160049091015550600191505b5095945050505050565b600154600160a060020a031681565b60015460009033600160a060020a0390811691161461036557600080fd5b60408051908101604090815260008083526001602080850191909152600160a060020a0386168252819052208151815560208201516001918201805460ff19169115159190911790559150505b919050565b6000602081905290815260409020805460019091015460ff1682565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061041457805160ff1916838001178555610441565b82800160010185558215610441579182015b82811115610441578251825591602001919060010190610426565b5b5061044e929150610452565b5090565b61047091905b8082111561044e5760008155600101610458565b5090565b905600a165627a7a723058209f57e670097977fafc5423e6f4da48d2d8a84ae38b7adb902591b865c7d9e4e40029`

// DeployProofOfExistence deploys a new Ethereum contract, binding an instance of ProofOfExistence to it.
func DeployProofOfExistence(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *ProofOfExistence, error) {
	parsed, err := abi.JSON(strings.NewReader(ProofOfExistenceABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(ProofOfExistenceBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ProofOfExistence{ProofOfExistenceCaller: ProofOfExistenceCaller{contract: contract}, ProofOfExistenceTransactor: ProofOfExistenceTransactor{contract: contract}}, nil
}

// ProofOfExistence is an auto generated Go binding around an Ethereum contract.
type ProofOfExistence struct {
	ProofOfExistenceCaller     // Read-only binding to the contract
	ProofOfExistenceTransactor // Write-only binding to the contract
}

// ProofOfExistenceCaller is an auto generated read-only Go binding around an Ethereum contract.
type ProofOfExistenceCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ProofOfExistenceTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ProofOfExistenceTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ProofOfExistenceSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ProofOfExistenceSession struct {
	Contract     *ProofOfExistence // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ProofOfExistenceCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ProofOfExistenceCallerSession struct {
	Contract *ProofOfExistenceCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts           // Call options to use throughout this session
}

// ProofOfExistenceTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ProofOfExistenceTransactorSession struct {
	Contract     *ProofOfExistenceTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts           // Transaction auth options to use throughout this session
}

// ProofOfExistenceRaw is an auto generated low-level Go binding around an Ethereum contract.
type ProofOfExistenceRaw struct {
	Contract *ProofOfExistence // Generic contract binding to access the raw methods on
}

// ProofOfExistenceCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ProofOfExistenceCallerRaw struct {
	Contract *ProofOfExistenceCaller // Generic read-only contract binding to access the raw methods on
}

// ProofOfExistenceTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ProofOfExistenceTransactorRaw struct {
	Contract *ProofOfExistenceTransactor // Generic write-only contract binding to access the raw methods on
}

// NewProofOfExistence creates a new instance of ProofOfExistence, bound to a specific deployed contract.
func NewProofOfExistence(address common.Address, backend bind.ContractBackend) (*ProofOfExistence, error) {
	contract, err := bindProofOfExistence(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ProofOfExistence{ProofOfExistenceCaller: ProofOfExistenceCaller{contract: contract}, ProofOfExistenceTransactor: ProofOfExistenceTransactor{contract: contract}}, nil
}

// NewProofOfExistenceCaller creates a new read-only instance of ProofOfExistence, bound to a specific deployed contract.
func NewProofOfExistenceCaller(address common.Address, caller bind.ContractCaller) (*ProofOfExistenceCaller, error) {
	contract, err := bindProofOfExistence(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &ProofOfExistenceCaller{contract: contract}, nil
}

// NewProofOfExistenceTransactor creates a new write-only instance of ProofOfExistence, bound to a specific deployed contract.
func NewProofOfExistenceTransactor(address common.Address, transactor bind.ContractTransactor) (*ProofOfExistenceTransactor, error) {
	contract, err := bindProofOfExistence(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &ProofOfExistenceTransactor{contract: contract}, nil
}

// bindProofOfExistence binds a generic wrapper to an already deployed contract.
func bindProofOfExistence(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ProofOfExistenceABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ProofOfExistence *ProofOfExistenceRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _ProofOfExistence.Contract.ProofOfExistenceCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ProofOfExistence *ProofOfExistenceRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.ProofOfExistenceTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ProofOfExistence *ProofOfExistenceRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.ProofOfExistenceTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ProofOfExistence *ProofOfExistenceCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _ProofOfExistence.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ProofOfExistence *ProofOfExistenceTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ProofOfExistence *ProofOfExistenceTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.contract.Transact(opts, method, params...)
}

// Devices is a free data retrieval call binding the contract method 0xe7b4cac6.
//
// Solidity: function devices( address) constant returns(numChanges uint256, exist bool)
func (_ProofOfExistence *ProofOfExistenceCaller) Devices(opts *bind.CallOpts, arg0 common.Address) (struct {
	NumChanges *big.Int
	Exist      bool
}, error) {
	ret := new(struct {
		NumChanges *big.Int
		Exist      bool
	})
	out := ret
	err := _ProofOfExistence.contract.Call(opts, out, "devices", arg0)
	return *ret, err
}

// Devices is a free data retrieval call binding the contract method 0xe7b4cac6.
//
// Solidity: function devices( address) constant returns(numChanges uint256, exist bool)
func (_ProofOfExistence *ProofOfExistenceSession) Devices(arg0 common.Address) (struct {
	NumChanges *big.Int
	Exist      bool
}, error) {
	return _ProofOfExistence.Contract.Devices(&_ProofOfExistence.CallOpts, arg0)
}

// Devices is a free data retrieval call binding the contract method 0xe7b4cac6.
//
// Solidity: function devices( address) constant returns(numChanges uint256, exist bool)
func (_ProofOfExistence *ProofOfExistenceCallerSession) Devices(arg0 common.Address) (struct {
	NumChanges *big.Int
	Exist      bool
}, error) {
	return _ProofOfExistence.Contract.Devices(&_ProofOfExistence.CallOpts, arg0)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_ProofOfExistence *ProofOfExistenceCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _ProofOfExistence.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_ProofOfExistence *ProofOfExistenceSession) Owner() (common.Address, error) {
	return _ProofOfExistence.Contract.Owner(&_ProofOfExistence.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_ProofOfExistence *ProofOfExistenceCallerSession) Owner() (common.Address, error) {
	return _ProofOfExistence.Contract.Owner(&_ProofOfExistence.CallOpts)
}

// AddChange is a paid mutator transaction binding the contract method 0x3ee54098.
//
// Solidity: function addChange(currentDevice address, currentOperation uint8, currentFolder string, currentFilename string, currentHashfile bytes32) returns(success bool)
func (_ProofOfExistence *ProofOfExistenceTransactor) AddChange(opts *bind.TransactOpts, currentDevice common.Address, currentOperation uint8, currentFolder string, currentFilename string, currentHashfile [32]byte) (*types.Transaction, error) {
	return _ProofOfExistence.contract.Transact(opts, "addChange", currentDevice, currentOperation, currentFolder, currentFilename, currentHashfile)
}

// AddChange is a paid mutator transaction binding the contract method 0x3ee54098.
//
// Solidity: function addChange(currentDevice address, currentOperation uint8, currentFolder string, currentFilename string, currentHashfile bytes32) returns(success bool)
func (_ProofOfExistence *ProofOfExistenceSession) AddChange(currentDevice common.Address, currentOperation uint8, currentFolder string, currentFilename string, currentHashfile [32]byte) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.AddChange(&_ProofOfExistence.TransactOpts, currentDevice, currentOperation, currentFolder, currentFilename, currentHashfile)
}

// AddChange is a paid mutator transaction binding the contract method 0x3ee54098.
//
// Solidity: function addChange(currentDevice address, currentOperation uint8, currentFolder string, currentFilename string, currentHashfile bytes32) returns(success bool)
func (_ProofOfExistence *ProofOfExistenceTransactorSession) AddChange(currentDevice common.Address, currentOperation uint8, currentFolder string, currentFilename string, currentHashfile [32]byte) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.AddChange(&_ProofOfExistence.TransactOpts, currentDevice, currentOperation, currentFolder, currentFilename, currentHashfile)
}

// AddDevice is a paid mutator transaction binding the contract method 0xb111cb84.
//
// Solidity: function addDevice(currentDevice address) returns(success bool)
func (_ProofOfExistence *ProofOfExistenceTransactor) AddDevice(opts *bind.TransactOpts, currentDevice common.Address) (*types.Transaction, error) {
	return _ProofOfExistence.contract.Transact(opts, "addDevice", currentDevice)
}

// AddDevice is a paid mutator transaction binding the contract method 0xb111cb84.
//
// Solidity: function addDevice(currentDevice address) returns(success bool)
func (_ProofOfExistence *ProofOfExistenceSession) AddDevice(currentDevice common.Address) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.AddDevice(&_ProofOfExistence.TransactOpts, currentDevice)
}

// AddDevice is a paid mutator transaction binding the contract method 0xb111cb84.
//
// Solidity: function addDevice(currentDevice address) returns(success bool)
func (_ProofOfExistence *ProofOfExistenceTransactorSession) AddDevice(currentDevice common.Address) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.AddDevice(&_ProofOfExistence.TransactOpts, currentDevice)
}

// RemoveDevice is a paid mutator transaction binding the contract method 0x1f7b6324.
//
// Solidity: function removeDevice(badDevice address) returns(success bool)
func (_ProofOfExistence *ProofOfExistenceTransactor) RemoveDevice(opts *bind.TransactOpts, badDevice common.Address) (*types.Transaction, error) {
	return _ProofOfExistence.contract.Transact(opts, "removeDevice", badDevice)
}

// RemoveDevice is a paid mutator transaction binding the contract method 0x1f7b6324.
//
// Solidity: function removeDevice(badDevice address) returns(success bool)
func (_ProofOfExistence *ProofOfExistenceSession) RemoveDevice(badDevice common.Address) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.RemoveDevice(&_ProofOfExistence.TransactOpts, badDevice)
}

// RemoveDevice is a paid mutator transaction binding the contract method 0x1f7b6324.
//
// Solidity: function removeDevice(badDevice address) returns(success bool)
func (_ProofOfExistence *ProofOfExistenceTransactorSession) RemoveDevice(badDevice common.Address) (*types.Transaction, error) {
	return _ProofOfExistence.Contract.RemoveDevice(&_ProofOfExistence.TransactOpts, badDevice)
}
