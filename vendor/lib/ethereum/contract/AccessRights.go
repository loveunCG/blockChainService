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

// AccessRightsABI is the input ABI used to generate the binding from.
const AccessRightsABI = "[{\"constant\":true,\"inputs\":[{\"name\":\"hashfolder\",\"type\":\"bytes32\"}],\"name\":\"getRight\",\"outputs\":[{\"name\":\"device\",\"type\":\"address\"},{\"name\":\"timestamp\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"rights\",\"outputs\":[{\"name\":\"hashfolder\",\"type\":\"bytes32\"},{\"name\":\"device\",\"type\":\"address\"},{\"name\":\"timestamp\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"hashfolder\",\"type\":\"bytes32\"},{\"name\":\"device\",\"type\":\"address\"}],\"name\":\"addRight\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

// AccessRightsBin is the compiled bytecode used for deploying new contracts.
const AccessRightsBin = `0x6060604052341561000f57600080fd5b5b60018054600160a060020a03191633600160a060020a03161790555b5b6102508061003c6000396000f300606060405263ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166325ee0f00811461005e5780638da5cb5b14610096578063d52fd095146100c5578063e7706fac14610107575b600080fd5b341561006957600080fd5b61007460043561013d565b604051600160a060020a03909216825260208201526040908101905180910390f35b34156100a157600080fd5b6100a9610168565b604051600160a060020a03909116815260200160405180910390f35b34156100d057600080fd5b6100db600435610177565b604051928352600160a060020a0390911660208301526040808301919091526060909101905180910390f35b341561011257600080fd5b610129600435600160a060020a03602435166101a1565b604051901515815260200160405180910390f35b60008181526020819052604090206001810154600290910154600160a060020a03909116905b915091565b600154600160a060020a031681565b6000602081905290815260409020805460018201546002909201549091600160a060020a03169083565b600060606040519081016040908152848252600160a060020a03841660208084019190915242828401526000868152908190522081518155602082015160018201805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a0392909216919091179055604082015160029091015550600190505b929150505600a165627a7a72305820e9b14c5a08626db578430daab64f26264ad78b8eb44b03dc925a4a13649e412a0029`

// DeployAccessRights deploys a new Ethereum contract, binding an instance of AccessRights to it.
func DeployAccessRights(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *AccessRights, error) {
	parsed, err := abi.JSON(strings.NewReader(AccessRightsABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(AccessRightsBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &AccessRights{AccessRightsCaller: AccessRightsCaller{contract: contract}, AccessRightsTransactor: AccessRightsTransactor{contract: contract}}, nil
}

// AccessRights is an auto generated Go binding around an Ethereum contract.
type AccessRights struct {
	AccessRightsCaller     // Read-only binding to the contract
	AccessRightsTransactor // Write-only binding to the contract
}

// AccessRightsCaller is an auto generated read-only Go binding around an Ethereum contract.
type AccessRightsCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AccessRightsTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AccessRightsTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AccessRightsSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AccessRightsSession struct {
	Contract     *AccessRights     // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AccessRightsCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AccessRightsCallerSession struct {
	Contract *AccessRightsCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts       // Call options to use throughout this session
}

// AccessRightsTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AccessRightsTransactorSession struct {
	Contract     *AccessRightsTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts       // Transaction auth options to use throughout this session
}

// AccessRightsRaw is an auto generated low-level Go binding around an Ethereum contract.
type AccessRightsRaw struct {
	Contract *AccessRights // Generic contract binding to access the raw methods on
}

// AccessRightsCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AccessRightsCallerRaw struct {
	Contract *AccessRightsCaller // Generic read-only contract binding to access the raw methods on
}

// AccessRightsTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AccessRightsTransactorRaw struct {
	Contract *AccessRightsTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAccessRights creates a new instance of AccessRights, bound to a specific deployed contract.
func NewAccessRights(address common.Address, backend bind.ContractBackend) (*AccessRights, error) {
	contract, err := bindAccessRights(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AccessRights{AccessRightsCaller: AccessRightsCaller{contract: contract}, AccessRightsTransactor: AccessRightsTransactor{contract: contract}}, nil
}

// NewAccessRightsCaller creates a new read-only instance of AccessRights, bound to a specific deployed contract.
func NewAccessRightsCaller(address common.Address, caller bind.ContractCaller) (*AccessRightsCaller, error) {
	contract, err := bindAccessRights(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &AccessRightsCaller{contract: contract}, nil
}

// NewAccessRightsTransactor creates a new write-only instance of AccessRights, bound to a specific deployed contract.
func NewAccessRightsTransactor(address common.Address, transactor bind.ContractTransactor) (*AccessRightsTransactor, error) {
	contract, err := bindAccessRights(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &AccessRightsTransactor{contract: contract}, nil
}

// bindAccessRights binds a generic wrapper to an already deployed contract.
func bindAccessRights(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AccessRightsABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AccessRights *AccessRightsRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _AccessRights.Contract.AccessRightsCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AccessRights *AccessRightsRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AccessRights.Contract.AccessRightsTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AccessRights *AccessRightsRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AccessRights.Contract.AccessRightsTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AccessRights *AccessRightsCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _AccessRights.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AccessRights *AccessRightsTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AccessRights.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AccessRights *AccessRightsTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AccessRights.Contract.contract.Transact(opts, method, params...)
}

// GetRight is a free data retrieval call binding the contract method 0x25ee0f00.
//
// Solidity: function getRight(hashfolder bytes32) constant returns(device address, timestamp uint256)
func (_AccessRights *AccessRightsCaller) GetRight(opts *bind.CallOpts, hashfolder [32]byte) (struct {
	Device    common.Address
	Timestamp *big.Int
}, error) {
	ret := new(struct {
		Device    common.Address
		Timestamp *big.Int
	})
	out := ret
	err := _AccessRights.contract.Call(opts, out, "getRight", hashfolder)
	return *ret, err
}

// GetRight is a free data retrieval call binding the contract method 0x25ee0f00.
//
// Solidity: function getRight(hashfolder bytes32) constant returns(device address, timestamp uint256)
func (_AccessRights *AccessRightsSession) GetRight(hashfolder [32]byte) (struct {
	Device    common.Address
	Timestamp *big.Int
}, error) {
	return _AccessRights.Contract.GetRight(&_AccessRights.CallOpts, hashfolder)
}

// GetRight is a free data retrieval call binding the contract method 0x25ee0f00.
//
// Solidity: function getRight(hashfolder bytes32) constant returns(device address, timestamp uint256)
func (_AccessRights *AccessRightsCallerSession) GetRight(hashfolder [32]byte) (struct {
	Device    common.Address
	Timestamp *big.Int
}, error) {
	return _AccessRights.Contract.GetRight(&_AccessRights.CallOpts, hashfolder)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_AccessRights *AccessRightsCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _AccessRights.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_AccessRights *AccessRightsSession) Owner() (common.Address, error) {
	return _AccessRights.Contract.Owner(&_AccessRights.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_AccessRights *AccessRightsCallerSession) Owner() (common.Address, error) {
	return _AccessRights.Contract.Owner(&_AccessRights.CallOpts)
}

// Rights is a free data retrieval call binding the contract method 0xd52fd095.
//
// Solidity: function rights( bytes32) constant returns(hashfolder bytes32, device address, timestamp uint256)
func (_AccessRights *AccessRightsCaller) Rights(opts *bind.CallOpts, arg0 [32]byte) (struct {
	Hashfolder [32]byte
	Device     common.Address
	Timestamp  *big.Int
}, error) {
	ret := new(struct {
		Hashfolder [32]byte
		Device     common.Address
		Timestamp  *big.Int
	})
	out := ret
	err := _AccessRights.contract.Call(opts, out, "rights", arg0)
	return *ret, err
}

// Rights is a free data retrieval call binding the contract method 0xd52fd095.
//
// Solidity: function rights( bytes32) constant returns(hashfolder bytes32, device address, timestamp uint256)
func (_AccessRights *AccessRightsSession) Rights(arg0 [32]byte) (struct {
	Hashfolder [32]byte
	Device     common.Address
	Timestamp  *big.Int
}, error) {
	return _AccessRights.Contract.Rights(&_AccessRights.CallOpts, arg0)
}

// Rights is a free data retrieval call binding the contract method 0xd52fd095.
//
// Solidity: function rights( bytes32) constant returns(hashfolder bytes32, device address, timestamp uint256)
func (_AccessRights *AccessRightsCallerSession) Rights(arg0 [32]byte) (struct {
	Hashfolder [32]byte
	Device     common.Address
	Timestamp  *big.Int
}, error) {
	return _AccessRights.Contract.Rights(&_AccessRights.CallOpts, arg0)
}

// AddRight is a paid mutator transaction binding the contract method 0xe7706fac.
//
// Solidity: function addRight(hashfolder bytes32, device address) returns(success bool)
func (_AccessRights *AccessRightsTransactor) AddRight(opts *bind.TransactOpts, hashfolder [32]byte, device common.Address) (*types.Transaction, error) {
	return _AccessRights.contract.Transact(opts, "addRight", hashfolder, device)
}

// AddRight is a paid mutator transaction binding the contract method 0xe7706fac.
//
// Solidity: function addRight(hashfolder bytes32, device address) returns(success bool)
func (_AccessRights *AccessRightsSession) AddRight(hashfolder [32]byte, device common.Address) (*types.Transaction, error) {
	return _AccessRights.Contract.AddRight(&_AccessRights.TransactOpts, hashfolder, device)
}

// AddRight is a paid mutator transaction binding the contract method 0xe7706fac.
//
// Solidity: function addRight(hashfolder bytes32, device address) returns(success bool)
func (_AccessRights *AccessRightsTransactorSession) AddRight(hashfolder [32]byte, device common.Address) (*types.Transaction, error) {
	return _AccessRights.Contract.AddRight(&_AccessRights.TransactOpts, hashfolder, device)
}
