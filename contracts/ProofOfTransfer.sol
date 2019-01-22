pragma solidity ^0.4.11;


contract ProofOfTransfer {

  // Definition of a proof of transfer
  struct Proof {
  address sender;
  address receiver;
  bytes32 hashfile;
  uint timestamp;
  }

  mapping (bytes32 => Proof) public proofs; // this allows to look up proof of transfer by the hashfile

  // Address of the smart contract owner
  address public owner;

  function ProofOfTransfer(){
    owner = msg.sender;
  }

  //this is used to store the proof of transfer of file at the block timestamp
  function addProof(address sender, address receiver, bytes32 hashfile) returns (bool success){
    proofs[hashfile] = Proof(sender, receiver, hashfile, block.timestamp);
    return true;
  }

  function getProof(bytes32 hashfile) constant returns (address sender, address receiver, uint timestamp){
    return (proofs[hashfile].sender, proofs[hashfile].receiver, proofs[hashfile].timestamp);
  }

}