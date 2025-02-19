require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();
const { ALCHEMY_API_KEY } = process.env;

module.exports = {
    solidity: {
        version: "0.8.20",
        settings: {
            optimizer: {
                enabled: true,
                runs: 200
            }
        }
    },
    paths: {
        sources: "./zkl-cross-chain/contracts/ethereum",
        tests: "./test",
        cache: "./cache",
        artifacts: "./artifacts"
    },
    networks: {
        sepolia: {
            url: process.env.ETH_RPC_URL,
            accounts: [process.env.PRIVATE_KEY]
        },
        hardhat: {
            chainId: 31337
        },
        localhost: {
            url: "http://127.0.0.1:8545",
            chainId: 31337
        }
    }
}; 