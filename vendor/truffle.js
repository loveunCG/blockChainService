module.exports = {
  networks: {
    development: {
      host: "localhost",
      port: 8545,
      network_id: "*" // Match any network id
    },
    rockchain:{
      network_id: 1496,
      host: "localhost",
      port: 8545
    },
    rpc: {
      host: 'localhost',
      port:8080
    }
  }
};
