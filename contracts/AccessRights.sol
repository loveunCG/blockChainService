pragma solidity ^0.4.11;


contract AccessRights {

    // Definition of a right
    struct Right {
    bytes32 hashfolder;
    address device;
    uint timestamp;
    }

    mapping (bytes32 => Right) public rights; // this allows to look up rights by the hashfolder

    // Address of the smart contract owner
    address public owner;

    function AccessRights(){
        owner = msg.sender;
    }

    //this is used to store the right grant to a device at the block timestamp
    function addRight(bytes32 hashfolder, address device) returns (bool success){
        rights[hashfolder] = Right(hashfolder, device, block.timestamp);
        return true;
    }

    function getRight(bytes32 hashfolder) constant returns (address device, uint timestamp){
        return (rights[hashfolder].device, rights[hashfolder].timestamp);
    }
}
