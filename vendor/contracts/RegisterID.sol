pragma solidity ^0.4.11;

contract RegisterID {

    event Register(address indexed _owner, uint256 _id);

    function register(uint256 id) {
        Register(msg.sender, id);
    }
}