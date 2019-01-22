package geth

import (
	randm "crypto/rand"
	"fmt"
	"io/ioutil"
	"math"
	"time"

	dappgeth "github.com/ethereum/go-ethereum/cmd/geth"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
)

//******** Global Ethereum Variables ********//
// var EthAccountAddress string // Global variable to safe account address
// var EthAccountPasswd string // Global variable to safe account password
// var BoolEthAccountAddressModel bool
// var JScommands []string // Store JS commands
// var BoolJScommands []bool // Select which command will run (TRUE: run it)
// var PathGethIPC string // Save the path to geth.ipc (needed to use the command "geth attach")
// var SyncingStatus *SyncingResult
// var BoolFastSyncEnabled bool
// var HashrateNow int64
// var PeersArray []*Peer
// var PeersQuantity int
// var BoolSyncingEthereum = false
// var CountersMetrics map[string]interface{}
// var StopGethChan chan bool
// var StopGethEndedChan chan bool // This channel indicates when Geth is completely stopped
// var GethNodeInfo *NodeInfo
// var EnodeAddress string // Global variable to safe node address
// var GethNodeInfoPorts []int
// var GethNodeInfo *p2p.NodeInfo

var BoolMiningEthereum bool   // Set to "false" to stop mining
var BoolJSConsoleBusy = false // prevent to run commands in JS console at the same time (all use the same array: dappgeth.JScommands)
var BoolGetEnodeAddress bool
var BoolGetEthAccountAddress bool
var EthereumNetwork string   // Select which network is going to be connected (ropsten, private, main) ropsten is default
var GethPath string          // Path to bootstrap and initialize the genesis block (depends on EthereumNetwork value)
var GethIsOn chan bool       // Hold the routine before it starts Geth again
var BoolGethIsOn = false     // Avoid dial to geth.ipc when Geth is turned off
var BoolShutDownGeth = false // Control the loop that allows start Geth again

func StartGeth(Network string, doneTypeNetwork chan bool) { // Geth commands are called here
	BoolGethIsOn = true
	node.PathGethIPC = ""
	GethIsOn = make(chan bool)
	EthereumNetwork = Network // Possible values: ropsten, private, or main
	doneTypeNetwork <- true
	GethPath = defaultConfigDir() + "/GethData/" + EthereumNetwork // Path to bootstrap and initialize the genesis block
	command := ""
	command_ := ""
	DisplayLog("Entering StartGeth")

	gethGenesisPath := GethPath + "/genesis.json"
	if EthereumNetwork == "private" {
		//	gethGenesisPath := defaultConfigDir() + "tendermint/genesis.json" // Path to the genesis .json file
		// Define genesis .json file
		genesisData := `{{"genesis_time":"2017-12-10T00:08:42.221905203+01:00","chain_id":"chain-mYY5rS","validators":[{"pub_key":{"type":"ed25519","data":"96A81AA39D3B6E8AC9FAB0E2B0AB9BEC546F581D454485F1AFD43F064DF2455F"},"power":1,"name":"mach0"},{"pub_key":{"type":"ed25519","data":"D88D96431FD724724B3942AE25C7A29D6D53EEF583ED0F7AD2ABB1DAA739D9CB"},"power":1,"name":"mach1"},{"pub_key":{"type":"ed25519","data":"85736A9B86D0FDC21A9237BC59BED08841B058AE52F1C351B1C7DFD2C9C615C4"},"power":1,"name":"mach2"},{"pub_key":{"type":"ed25519","data":"371F41C14E99B9CC2271E9C34D46E17BCB5762B36548131AC390C92527286C50"},"power":1,"name":"mach3"}],"app_hash":""}

		}`
		err := ioutil.WriteFile(gethGenesisPath, []byte(genesisData), 0644) // Create genesis .json file
		dealwithErr(err)
		command = "tendermint init --home " + gethGenesisPath // Bootstrap and initialize a new genesis block
		command_ = "ethermint --datadir " + defaultConfigDir() + "init"
	} else if EthereumNetwork == "rockchain" {
		//		command = "geth --metrics --fast --cache 1024 --trie-cache-gens 1024 --port 30384 --datadir " + GethPath // Connect to the main Ethereum network
	} else { // EthereumNetwork == "ropsten"
		gethGenesisPath := defaultConfigDir() + "/genesis.json"
		genesisData := `{{"genesis_time":"2017-12-10T00:08:42.221905203+01:00","chain_id":"chain-mYY5rS","validators":[{"pub_key":{"type":"ed25519","data":"96A81AA39D3B6E8AC9FAB0E2B0AB9BEC546F581D454485F1AFD43F064DF2455F"},"power":1,"name":"mach0"},{"pub_key":{"type":"ed25519","data":"D88D96431FD724724B3942AE25C7A29D6D53EEF583ED0F7AD2ABB1DAA739D9CB"},"power":1,"name":"mach1"},{"pub_key":{"type":"ed25519","data":"85736A9B86D0FDC21A9237BC59BED08841B058AE52F1C351B1C7DFD2C9C615C4"},"power":1,"name":"mach2"},{"pub_key":{"type":"ed25519","data":"371F41C14E99B9CC2271E9C34D46E17BCB5762B36548131AC390C92527286C50"},"power":1,"name":"mach3"}],"app_hash":""}}`
		err := ioutil.WriteFile(gethGenesisPath, []byte(genesisData), 0644) // Create genesis .json file
		dealwithErr(err)
		command = "tendermint init " //+ gethGenesisPath // Bootstrap and initialize a new genesis block
		command_ = "ethermint init " //+ defaultConfigDir() + "init"
		//command = "geth --testnet --metrics --fast --cache 1024 --trie-cache-gens 1024 --port 30384 --datadir " + GethPath // Connect to the Ropsten testnet Ethereum network (DEFAULT)
	}

	fmt.Println("$", command)
	dappgeth.MainGeth(command)
	time.Sleep(3 * time.Second)
	fmt.Println("$", command_)
	dappgeth.MainGeth(command_)
	if EthereumNetwork == "private" {
		time.Sleep(3 * time.Second)
		command = "tendermint --home " + gethGenesisPath + "node --pex"
		command_ = "ethermint --datadir" + defaultConfigDir() + "--rpc --rpcaddr=0.0.0.0 --ws --wsaddr=0.0.0.0 --rpcapi eth,net,web3,personal,admin"
		fmt.Println("$", command)
		dappgeth.MainGeth(command)
		time.Sleep(3 * time.Second)
		fmt.Println("$", command_)
		dappgeth.MainGeth(command_)
		time.Sleep(3 * time.Second)
		fmt.Println("$", "geth attach localhost:8545")
		dappgeth.MainGeth("geth attach localhost:8545")

	}

}

func StopGeth() {
	BoolGethIsOn = false
	utils.StopGethChan <- true
	<-ethdb.StopGethEndedChan // Geth is completely stopped
	time.Sleep(1500 * time.Millisecond)
	log.Info("Geth is completely stopped!")
	node.PathGethIPC = ""
}

func GetMyEthAddresses(doneGethInit chan bool) { // Create an Ethereum account if needed
	dappgeth.JScommands = []string{}
	dappgeth.BoolJScommands = []bool{}

	for { // Waits until geth.ipc is created
		if node.PathGethIPC != "" {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if BoolGetEnodeAddress {
		RunConsoleCommands("admin.nodeInfo")
	}

	if BoolGetEthAccountAddress {
		byte32Aux := make([]byte, 1000)
		randm.Read(byte32Aux)
		//		console.EthAccountPasswd = ethhash.KeccakByte(byte32Aux, 512)
		RunConsoleCommands("personal.newAccount()")
	}

	RunConsoleCommands("personal.listAccounts")

	doneGethInit <- true
}

func StartMining() {
	BoolMiningEthereum = true
	// Start mining
	RunConsoleCommands("eth.accounts[0]", "miner.setEtherbase(eth.accounts[0])", "miner.start()", "eth.blockNumber", "miner.getHashrate()")

	// Check how mining is going
	for { // set "BoolMiningEthereum" = false to stop mining
		if !BoolMiningEthereum {
			break
		}
		RunConsoleCommands("eth.blockNumber", "miner.getHashrate()")
		time.Sleep(10 * time.Second)
	}

	// Stop mining
	RunConsoleCommands("miner.stop()")
}

func RunConsoleCommands(commands ...string) { // Geth commands are called with it
	switch BoolGethIsOn {
	case false: // Geth is OFF
		log.Info("Geth is off:", GethIsOn)
	default:
		commandsArray := []string{}

		for { // Waits until geth.ipc is created
			if node.PathGethIPC != "" {
				break
			}
			time.Sleep(1 * time.Second)
		}

		for _, command := range commands {
			commandsArray = append(commandsArray, command)
		}

		dappgeth.JScommands = commandsArray
		dappgeth.BoolJScommands = []bool{}
		command := "geth attach " + node.PathGethIPC // Start an interactive JavaScript environment
		for {
			if !BoolJSConsoleBusy {
				BoolJSConsoleBusy = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		dappgeth.MainGeth(command)
		BoolJSConsoleBusy = false
	}
}

func GetGethMetrics() (chainArray, p2pInboundConnectsArray, p2pInboundTrafficArray, p2pOutboundConnectsArray, p2pOutboundTrafficArray, systemDiskReadcountArray, systemDiskReaddataArray, systemDiskWritecountArray, systemDiskWritedataArray, systemMemoryAllocsArray, systemMemoryFreesArray, systemMemoryInuseArray, systemMemoryPausesArray []float64) {
	powE9 := math.Pow(10, 9)
	RunConsoleCommands("debug.metrics(true)")

	// CHAIN
	chainInsertsAvgRate01Min := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["AvgRate01Min"].(float64)
	chainInsertsAvgRate05Min := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["AvgRate05Min"].(float64)
	chainInsertsAvgRate15Min := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["AvgRate15Min"].(float64)
	chainInsertsMeanRate := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["MeanRate"].(float64)
	chainInsertsOverall := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["Overall"].(float64)
	chainInsertsPercentiles5 := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["Percentiles"].(map[string]interface{})["5"].(float64) / powE9
	chainInsertsPercentiles20 := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["Percentiles"].(map[string]interface{})["20"].(float64) / powE9
	chainInsertsPercentiles50 := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["Percentiles"].(map[string]interface{})["50"].(float64) / powE9
	chainInsertsPercentiles80 := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["Percentiles"].(map[string]interface{})["80"].(float64) / powE9
	chainInsertsPercentiles95 := node.CountersMetrics["chain"].(map[string]interface{})["inserts"].(map[string]interface{})["Percentiles"].(map[string]interface{})["95"].(float64) / powE9
	chainArray = []float64{chainInsertsAvgRate01Min, // [/s]
		chainInsertsAvgRate05Min,  // [/s]
		chainInsertsAvgRate15Min,  // [/s]
		chainInsertsMeanRate,      // [/s]
		chainInsertsOverall,       // []
		chainInsertsPercentiles5,  // [s]
		chainInsertsPercentiles20, // [s]
		chainInsertsPercentiles50, // [s]
		chainInsertsPercentiles80, // [s]
		chainInsertsPercentiles95, // [s]
	}

	// chain: {
	//   inserts: {
	//     AvgRate01Min: 0.058319112424357264,
	//     AvgRate05Min: 0.07317033683084097,
	//     AvgRate15Min: 0.07916264794717423,
	//     MeanRate: 0.49496617955209643,
	//     Overall: 3435,
	//     Percentiles: {
	//       20: 2661753.2,
	//       5: 662697.05,
	//       50: 10642755.5,
	//       80: 35975543.60000002,
	//       95: 263023303.44999993
	//     }
	//   }
	// }

	// P2P
	p2pInboundConnectsAvgRate01Min := node.CountersMetrics["p2p"].(map[string]interface{})["InboundConnects"].(map[string]interface{})["AvgRate01Min"].(float64)
	p2pInboundConnectsAvgRate05Min := node.CountersMetrics["p2p"].(map[string]interface{})["InboundConnects"].(map[string]interface{})["AvgRate05Min"].(float64)
	p2pInboundConnectsAvgRate15Min := node.CountersMetrics["p2p"].(map[string]interface{})["InboundConnects"].(map[string]interface{})["AvgRate15Min"].(float64)
	p2pInboundConnectsMeanRate := node.CountersMetrics["p2p"].(map[string]interface{})["InboundConnects"].(map[string]interface{})["MeanRate"].(float64)
	p2pInboundConnectsOverall := node.CountersMetrics["p2p"].(map[string]interface{})["InboundConnects"].(map[string]interface{})["Overall"].(float64)
	p2pInboundConnectsArray = []float64{p2pInboundConnectsAvgRate01Min, // [/s]
		p2pInboundConnectsAvgRate05Min, // [/s]
		p2pInboundConnectsAvgRate15Min, // [/s]
		p2pInboundConnectsMeanRate,     // [/s]
		p2pInboundConnectsOverall,      // [/s]
	}
	p2pInboundTrafficAvgRate01Min := node.CountersMetrics["p2p"].(map[string]interface{})["InboundTraffic"].(map[string]interface{})["AvgRate01Min"].(float64)
	p2pInboundTrafficAvgRate05Min := node.CountersMetrics["p2p"].(map[string]interface{})["InboundTraffic"].(map[string]interface{})["AvgRate05Min"].(float64)
	p2pInboundTrafficAvgRate15Min := node.CountersMetrics["p2p"].(map[string]interface{})["InboundTraffic"].(map[string]interface{})["AvgRate15Min"].(float64)
	p2pInboundTrafficMeanRate := node.CountersMetrics["p2p"].(map[string]interface{})["InboundTraffic"].(map[string]interface{})["MeanRate"].(float64)
	p2pInboundTrafficOverall := node.CountersMetrics["p2p"].(map[string]interface{})["InboundTraffic"].(map[string]interface{})["Overall"].(float64)
	p2pInboundTrafficArray = []float64{p2pInboundTrafficAvgRate01Min, // [/s]
		p2pInboundTrafficAvgRate05Min, // [/s]
		p2pInboundTrafficAvgRate15Min, // [/s]
		p2pInboundTrafficMeanRate,     // [/s]
		p2pInboundTrafficOverall,      // [/s]
	}
	p2pOutboundConnectsAvgRate01Min := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundConnects"].(map[string]interface{})["AvgRate01Min"].(float64)
	p2pOutboundConnectsAvgRate05Min := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundConnects"].(map[string]interface{})["AvgRate05Min"].(float64)
	p2pOutboundConnectsAvgRate15Min := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundConnects"].(map[string]interface{})["AvgRate15Min"].(float64)
	p2pOutboundConnectsMeanRate := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundConnects"].(map[string]interface{})["MeanRate"].(float64)
	p2pOutboundConnectsOverall := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundConnects"].(map[string]interface{})["Overall"].(float64)
	p2pOutboundConnectsArray = []float64{p2pOutboundConnectsAvgRate01Min, // [/s]
		p2pOutboundConnectsAvgRate05Min, // [/s]
		p2pOutboundConnectsAvgRate15Min, // [/s]
		p2pOutboundConnectsMeanRate,     // [/s]
		p2pOutboundConnectsOverall,      // [/s]
	}
	p2pOutboundTrafficAvgRate01Min := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundTraffic"].(map[string]interface{})["AvgRate01Min"].(float64)
	p2pOutboundTrafficAvgRate05Min := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundTraffic"].(map[string]interface{})["AvgRate05Min"].(float64)
	p2pOutboundTrafficAvgRate15Min := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundTraffic"].(map[string]interface{})["AvgRate15Min"].(float64)
	p2pOutboundTrafficMeanRate := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundTraffic"].(map[string]interface{})["MeanRate"].(float64)
	p2pOutboundTrafficOverall := node.CountersMetrics["p2p"].(map[string]interface{})["OutboundTraffic"].(map[string]interface{})["Overall"].(float64)
	p2pOutboundTrafficArray = []float64{p2pOutboundTrafficAvgRate01Min, // [/s]
		p2pOutboundTrafficAvgRate05Min, // [/s]
		p2pOutboundTrafficAvgRate15Min, // [/s]
		p2pOutboundTrafficMeanRate,     // [/s]
		p2pOutboundTrafficOverall,      // [/s]
	}

	// p2p: {
	//   InboundConnects: {
	//     AvgRate01Min: 0.36044317959145145,
	//     AvgRate05Min: 0.08346651042525481,
	//     AvgRate15Min: 0.02852760040723967,
	//     MeanRate: 0.8545572890762899,
	//     Overall: 33
	//   },
	//   InboundTraffic: {
	//     AvgRate01Min: 334.72907253266663,
	//     AvgRate05Min: 77.97496947863726,
	//     AvgRate15Min: 26.680179714271485,
	//     MeanRate: 855.6924439598582,
	//     Overall: 33086
	//   },
	//   OutboundConnects: {
	//     AvgRate01Min: 0.28529658408741704,
	//     AvgRate05Min: 0.06711082134984471,
	//     AvgRate15Min: 0.023006203343039083,
	//     MeanRate: 0.7842860819246446,
	//     Overall: 29
	//   },
	//   OutboundTraffic: {
	//     AvgRate01Min: 399.86034840070766,
	//     AvgRate05Min: 93.52116723873766,
	//     AvgRate15Min: 32.02225138702515,
	//     MeanRate: 1040.7952749714104,
	//     Overall: 40241
	//   }
	// }

	// SYSTEM
	// DISK
	systemDiskReadcountAvgRate01Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readcount"].(map[string]interface{})["AvgRate01Min"].(float64)
	systemDiskReadcountAvgRate05Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readcount"].(map[string]interface{})["AvgRate05Min"].(float64)
	systemDiskReadcountAvgRate15Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readcount"].(map[string]interface{})["AvgRate15Min"].(float64)
	systemDiskReadcountMeanRate := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readcount"].(map[string]interface{})["MeanRate"].(float64)
	systemDiskReadcountOverall := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readcount"].(map[string]interface{})["Overall"].(float64)
	systemDiskReadcountArray = []float64{systemDiskReadcountAvgRate01Min, // [/s]
		systemDiskReadcountAvgRate05Min, // [/s]
		systemDiskReadcountAvgRate15Min, // [/s]
		systemDiskReadcountMeanRate,     // [/s]
		systemDiskReadcountOverall,      // [/s]
	}
	systemDiskReaddataAvgRate01Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readdata"].(map[string]interface{})["AvgRate01Min"].(float64)
	systemDiskReaddataAvgRate05Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readdata"].(map[string]interface{})["AvgRate05Min"].(float64)
	systemDiskReaddataAvgRate15Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readdata"].(map[string]interface{})["AvgRate15Min"].(float64)
	systemDiskReaddataMeanRate := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readdata"].(map[string]interface{})["MeanRate"].(float64)
	systemDiskReaddataOverall := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["readdata"].(map[string]interface{})["Overall"].(float64)
	systemDiskReaddataArray = []float64{systemDiskReaddataAvgRate01Min, // [/s]
		systemDiskReaddataAvgRate05Min, // [/s]
		systemDiskReaddataAvgRate15Min, // [/s]
		systemDiskReaddataMeanRate,     // [/s]
		systemDiskReaddataOverall,      // [/s]
	}
	systemDiskWritecountAvgRate01Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writecount"].(map[string]interface{})["AvgRate01Min"].(float64)
	systemDiskWritecountAvgRate05Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writecount"].(map[string]interface{})["AvgRate05Min"].(float64)
	systemDiskWritecountAvgRate15Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writecount"].(map[string]interface{})["AvgRate15Min"].(float64)
	systemDiskWritecountMeanRate := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writecount"].(map[string]interface{})["MeanRate"].(float64)
	systemDiskWritecountOverall := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writecount"].(map[string]interface{})["Overall"].(float64)
	systemDiskWritecountArray = []float64{systemDiskWritecountAvgRate01Min, // [/s]
		systemDiskWritecountAvgRate05Min, // [/s]
		systemDiskWritecountAvgRate15Min, // [/s]
		systemDiskWritecountMeanRate,     // [/s]
		systemDiskWritecountOverall,      // [/s]
	}
	systemDiskWritedataAvgRate01Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writedata"].(map[string]interface{})["AvgRate01Min"].(float64)
	systemDiskWritedataAvgRate05Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writedata"].(map[string]interface{})["AvgRate05Min"].(float64)
	systemDiskWritedataAvgRate15Min := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writedata"].(map[string]interface{})["AvgRate15Min"].(float64)
	systemDiskWritedataMeanRate := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writedata"].(map[string]interface{})["MeanRate"].(float64)
	systemDiskWritedataOverall := node.CountersMetrics["system"].(map[string]interface{})["disk"].(map[string]interface{})["writedata"].(map[string]interface{})["Overall"].(float64)
	systemDiskWritedataArray = []float64{systemDiskWritedataAvgRate01Min, // [/s]
		systemDiskWritedataAvgRate05Min, // [/s]
		systemDiskWritedataAvgRate15Min, // [/s]
		systemDiskWritedataMeanRate,     // [/s]
		systemDiskWritedataOverall,      // [/s]
	}

	// system: {
	//   disk: {
	//     readcount: {
	//       AvgRate01Min: 94.53262968278493,
	//       AvgRate05Min: 72.18748699585421,
	//       AvgRate15Min: 66.13824003905245,
	//       MeanRate: 151.4142233278347,
	//       Overall: 5453
	//     },
	//     readdata: {
	//       AvgRate01Min: 728880.8898932381,
	//       AvgRate05Min: 918804.0118064723,
	//       AvgRate15Min: 953705.6327993373,
	//       MeanRate: 500284.1639060301,
	//       Overall: 18017124
	//     },
	//     writecount: {
	//       AvgRate01Min: 152.26725776059888,
	//       AvgRate05Min: 170.58345353398954,
	//       AvgRate15Min: 173.05651654935093,
	//       MeanRate: 145.7220168998973,
	//       Overall: 5248
	//     },
	//     writedata: {
	//       AvgRate01Min: 587754.3742191641,
	//       AvgRate05Min: 734527.6641757037,
	//       AvgRate15Min: 760837.3521340019,
	//       MeanRate: 418627.21880363213,
	//       Overall: 15076345
	//     }
	//   }
	// }

	// SYSTEM
	// MEMORY
	systemMemoryAllocsAvgRate01Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["allocs"].(map[string]interface{})["AvgRate01Min"].(float64)
	systemMemoryAllocsAvgRate05Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["allocs"].(map[string]interface{})["AvgRate05Min"].(float64)
	systemMemoryAllocsAvgRate15Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["allocs"].(map[string]interface{})["AvgRate15Min"].(float64)
	systemMemoryAllocsMeanRate := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["allocs"].(map[string]interface{})["MeanRate"].(float64)
	systemMemoryAllocsOverall := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["allocs"].(map[string]interface{})["Overall"].(float64)
	systemMemoryAllocsArray = []float64{systemMemoryAllocsAvgRate01Min, // [/s]
		systemMemoryAllocsAvgRate05Min, // [/s]
		systemMemoryAllocsAvgRate15Min, // [/s]
		systemMemoryAllocsMeanRate,     // [/s]
		systemMemoryAllocsOverall,      // [/s]
	}
	systemMemoryFreesAvgRate01Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["frees"].(map[string]interface{})["AvgRate01Min"].(float64)
	systemMemoryFreesAvgRate05Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["frees"].(map[string]interface{})["AvgRate05Min"].(float64)
	systemMemoryFreesAvgRate15Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["frees"].(map[string]interface{})["AvgRate15Min"].(float64)
	systemMemoryFreesMeanRate := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["frees"].(map[string]interface{})["MeanRate"].(float64)
	systemMemoryFreesOverall := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["frees"].(map[string]interface{})["Overall"].(float64)
	systemMemoryFreesArray = []float64{systemMemoryFreesAvgRate01Min, // [/s]
		systemMemoryFreesAvgRate05Min, // [/s]
		systemMemoryFreesAvgRate15Min, // [/s]
		systemMemoryFreesMeanRate,     // [/s]
		systemMemoryFreesOverall,      // [/s]
	}
	systemMemoryInuseAvgRate01Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["inuse"].(map[string]interface{})["AvgRate01Min"].(float64)
	systemMemoryInuseAvgRate05Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["inuse"].(map[string]interface{})["AvgRate05Min"].(float64)
	systemMemoryInuseAvgRate15Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["inuse"].(map[string]interface{})["AvgRate15Min"].(float64)
	systemMemoryInuseMeanRate := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["inuse"].(map[string]interface{})["MeanRate"].(float64)
	systemMemoryInuseOverall := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["inuse"].(map[string]interface{})["Overall"].(float64)
	systemMemoryInuseArray = []float64{systemMemoryInuseAvgRate01Min, // [/s]
		systemMemoryInuseAvgRate05Min, // [/s]
		systemMemoryInuseAvgRate15Min, // [/s]
		systemMemoryInuseMeanRate,     // [/s]
		systemMemoryInuseOverall,      // [/s]
	}
	systemMemoryPausesAvgRate01Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["pauses"].(map[string]interface{})["AvgRate01Min"].(float64)
	systemMemoryPausesAvgRate05Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["pauses"].(map[string]interface{})["AvgRate05Min"].(float64)
	systemMemoryPausesAvgRate15Min := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["pauses"].(map[string]interface{})["AvgRate15Min"].(float64)
	systemMemoryPausesMeanRate := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["pauses"].(map[string]interface{})["MeanRate"].(float64)
	systemMemoryPausesOverall := node.CountersMetrics["system"].(map[string]interface{})["memory"].(map[string]interface{})["pauses"].(map[string]interface{})["Overall"].(float64)
	systemMemoryPausesArray = []float64{systemMemoryPausesAvgRate01Min, // [/s]
		systemMemoryPausesAvgRate05Min, // [/s]
		systemMemoryPausesAvgRate15Min, // [/s]
		systemMemoryPausesMeanRate,     // [/s]
		systemMemoryPausesOverall,      // [/s]
	}

	// system: {
	//   memory: {
	//     allocs: {
	//       AvgRate01Min: 19674.436383467295,
	//       AvgRate05Min: 27861.992305769527,
	//       AvgRate15Min: 29563.199922070115,
	//       MeanRate: 7300.423791196295,
	//       Overall: 262917
	//     },
	//     frees: {
	//       AvgRate01Min: 8426.72439963375,
	//       AvgRate05Min: 12510.285046528965,
	//       AvgRate15Min: 13364.08747504606,
	//       MeanRate: 2040.212658642602,
	//       Overall: 73476
	//     },
	//     inuse: {
	//       AvgRate01Min: 34270489.68728196,
	//       AvgRate05Min: 50744151.66294443,
	//       AvgRate15Min: 54182831.20646346,
	//       MeanRate: 8570032.233980186,
	//       Overall: 308639880
	//     },
	//     pauses: {
	//       AvgRate01Min: 2822636.962780127,
	//       AvgRate05Min: 4210879.533550534,
	//       AvgRate15Min: 4501173.803002889,
	//       MeanRate: 646104.4693291964,
	//       Overall: 23268708
	//     }
	//   }
	// }

	return
}
