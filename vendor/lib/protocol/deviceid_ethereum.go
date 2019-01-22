package protocol

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

func (n DeviceID) IsValidEthereumAddress() bool {
	for _, b := range n[common.AddressLength:] {
		if b != 0 {
			return false
		}
	}
	return true
}

func (n DeviceID) EthereumAddress() (common.Address, error) {
	if !n.IsValidEthereumAddress() {
		return common.Address{}, fmt.Errorf("DeviceID is not a valid Ethereum address (must be zero padded)")
	}
	var addr common.Address
	copy(addr[:], n[:common.AddressLength])
	return addr, nil
}

func (n DeviceID) BigInt() *big.Int {
	var i big.Int
	i.SetBytes(n[:])
	return &i
}

func DeviceIDFromEthereumAddress(addr common.Address) DeviceID {
	var n DeviceID
	copy(n[:], addr.Bytes())
	return n
}

func DeviceIDFromBigInt(i *big.Int) DeviceID {
	var n DeviceID
	copy(n[:], i.Bytes())
	return n
}
