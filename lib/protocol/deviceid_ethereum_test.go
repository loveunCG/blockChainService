package protocol_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/dappbox/dappbox/lib/protocol"
)

func TestEthereumDeviceID(t *testing.T) {
	var addr common.Address

	addr[0] = 42
	addr[common.AddressLength-1] = 42

	id := protocol.DeviceIDFromEthereumAddress(addr)

	if !id.IsValidEthereumAddress() {
		t.Error("DeviceID derived from address should always be valid")
	}

	if roundtrip, err := id.EthereumAddress(); roundtrip != addr || err != nil {
		t.Error("Addresses should round trip without error")
	}

	id[common.AddressLength] = 3

	if id.IsValidEthereumAddress() {
		t.Error("DeviceID derived with trailing non zero bytes should no longer be valid")
	}

	if ret, err := id.EthereumAddress(); (ret != common.Address{} || err == nil) {
		t.Error("DeviceID should fail to convert to Ethereum address when it contains too many non zero bytes")
	}
}

func TestEthereumIDsFitInDeviceIDs(t *testing.T) {
	// We rely on the improbability (2^-(12*8)) of device IDs being valid
	// Ethereum addresses, so there should be room to spare here
	if protocol.DeviceIDLength-common.AddressLength != 12 {
		t.Error("Ethereum addresses no longer fit in dappbox DeviceIDs")
	}
}
