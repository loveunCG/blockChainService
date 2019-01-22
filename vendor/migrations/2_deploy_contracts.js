var ownership = artifacts.require("./Ownership.sol");
var proofofexistence = artifacts.require("./ProofOfExistence.sol");
var proofoftransfer = artifacts.require("./ProofOfTransfer.sol");
var accessrights = artifacts.require("./AccessRights.sol");
var registerid = artifacts.require("./RegisterID.sol");

module.exports = function(deployer, network) {
    var owner = web3.eth.accounts[0];

	console.log("Owner address: " + owner);

    console.log("Ownership deployment ...");
        return deployer.deploy(ownership, { from: owner }).then(function(){
	        console.log("Ownership address : " + ownership.address);

	        console.log("ProofOfExistence deployment ...");
                return deployer.deploy(proofofexistence, { from: owner }).then(function(){
                        console.log("ProofOfExistence address : " + proofofexistence.address);

                        console.log("ProofOfTransfer deployment ...");
                            return deployer.deploy(proofoftransfer, { from: owner }).then(function(){
                                        console.log("ProofOfTransfer address : " + proofoftransfer.address);

                                            console.log("RegisterID deployment ...");
                                                    return deployer.deploy(registerid, { from: owner }).then(function(){
                                                                console.log("RegisterID address : " + registerid.address);

                                                                        console.log("AccessRights deployment ...");
                                                                                return deployer.deploy(accessrights, { from: owner }).then(function(){
                                                                                            console.log("AccessRights address : " + accessrights.address);
                                                                                });
                                                    });
                            });
                });
	    });

};
