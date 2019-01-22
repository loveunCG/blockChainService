pragma solidity ^0.4.11;

contract Ownership {

  struct ownerDetails {
  uint timestamp;
  address ownerfile;
  bytes32 hashfile;
  }

  address public owner;

  mapping (bytes32 => ownerDetails) public owners; // this allows to look up the owner of the file

  // Throws if called by any account other than the owner.
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  // The Ownable constructor sets the original `owner` of the contract to the sender account
  function Ownership() {
    owner = msg.sender;
  }

  //this is used to store the owner of file at the block timestamp
  function addDetails(address ownerfile, bytes32 hashfile) returns (bool success) {
    owners[hashfile] = ownerDetails(block.timestamp, ownerfile, hashfile);
    return true;
  }

  //this is used to get owner and file information
  function getDetails(bytes32 hashfile) returns (uint timestamp, address ownerfile) {
    return (owners[hashfile].timestamp, owners[hashfile].ownerfile);
  }

  // @dev Allows the current owner to transfer control of his file to a newOwner.
  // @param newOwner The address to transfer ownership to.
  function transferOwnership(address newOwner, bytes32 hashfile) onlyOwner {
    require(newOwner != address(0));
    owners[hashfile].ownerfile = newOwner;
    owners[hashfile].timestamp = block.timestamp;
  }

}