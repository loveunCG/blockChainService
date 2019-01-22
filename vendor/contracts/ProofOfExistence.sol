pragma solidity ^0.4.11;

contract ProofOfExistence {

  enum Operation { Add, Update, Remove}

  // Definition of a change
  struct Change {
  Operation operation;
  string folder;
  string filename;
  bytes32 hashfile;
  uint timestamp;
  }

  // Each device maintains a list of changes
  struct Device {
  uint numChanges;
  bool exist;
  mapping (uint => Change) changes;
  }

  mapping (address => Device) public devices; // List of devices

  // Address of the smart contract owner
  address public owner;

  // Throws if called by any account other than the owner.
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function ProofOfExistence() {
    owner = msg.sender;
  }

  function addDevice(address currentDevice) returns (bool success){
    require(msg.sender == owner);
    devices[currentDevice] = Device(0, true);
    return true;
  }

  function addChange(address currentDevice, Operation currentOperation, string currentFolder,
  string currentFilename, bytes32 currentHashfile) returns (bool success) {
    Device storage d = devices[currentDevice];
    require(d.exist);
    d.changes[d.numChanges++] = Change(currentOperation, currentFolder, currentFilename, currentHashfile, block.timestamp);
    return true;
  }

  function removeDevice(address badDevice) onlyOwner returns (bool success) {
    delete devices[badDevice];
    return true;
  }

}