const hre = require("hardhat");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  // 1. Ortam değişkenlerini yükle
  const DEPLOYER = process.env.DEPLOYER_ADDRESS;
  const WORMHOLE_ADDRESS = process.env.WORMHOLE_ADDRESS;
  const SOLANA_CHAIN_ID = process.env.SOLANA_CHAIN_ID || 1;

  // 2. Provider ve signer'ı al
  const [deployer] = await ethers.getSigners();
  const provider = deployer.provider;

  // 3. Gas fiyatını kontrol et
  const feeData = await provider.getFeeData();
  const gasPrice = feeData.gasPrice;
  const estimatedGasPrice = gasPrice * BigInt(120) / BigInt(100); // %20 buffer

  // 4. Kontrat fabrikasını oluştur
  const CrossChainMessaging = await ethers.getContractFactory("CrossChainMessaging");
  
  // 5. Deployment parametrelerini kontrol et
  if (!WORMHOLE_ADDRESS) {
    throw new Error("WORMHOLE_ADDRESS environment variable not set");
  }

  console.log("╔════════════════════════════════════════════╗");
  console.log("║          CrossChainMessaging Deploy        ║");
  console.log("╠════════════════════════════════════════════╣");
  console.log(`║ Network: ${hre.network.name.padEnd(25)} ║`);
  console.log(`║ Deployer: ${DEPLOYER.padEnd(25)} ║`);
  console.log(`║ Wormhole Address: ${WORMHOLE_ADDRESS} ║`);
  console.log(`║ Solana Chain ID: ${SOLANA_CHAIN_ID.toString().padEnd(10)} ║`);
  console.log(`║ Gas Price: ${ethers.formatUnits(estimatedGasPrice, "gwei")} gwei ║`);
  console.log("╚════════════════════════════════════════════╝");

  // 6. Kontratı deploy et
  console.log("\nDeploying contract...");
  const deployTx = await CrossChainMessaging.deploy(
    WORMHOLE_ADDRESS,
    SOLANA_CHAIN_ID,
    {
      maxFeePerGas: estimatedGasPrice,
      maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
      gasLimit: 3000000
    }
  );

  // 7. Deploy işlemini bekle
  console.log("Waiting for deployment transaction...");
  const contract = await deployTx.waitForDeployment();
  const contractAddress = await contract.getAddress();
  
  console.log("\n✅ Contract deployed to:", contractAddress);

  // 8. ABI ve adresi kaydet
  const contractDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(contractDir)) {
    fs.mkdirSync(contractDir, { recursive: true });
  }

  const deploymentInfo = {
    network: hre.network.name,
    contractAddress: contractAddress,
    deployer: DEPLOYER,
    wormholeAddress: WORMHOLE_ADDRESS,
    solanaChainId: SOLANA_CHAIN_ID,
    timestamp: new Date().toISOString(),
    blockNumber: await provider.getBlockNumber(),
    gasPrice: estimatedGasPrice.toString()
  };

  fs.writeFileSync(
    path.join(contractDir, `deployment-${hre.network.name}.json`),
    JSON.stringify(deploymentInfo, null, 2)
  );

  console.log("\n📁 Deployment info saved to deployments directory");

  // 9. Doğrulama için gerekli komutu göster
  console.log("\n🔍 To verify on Etherscan run:");
  console.log(`npx hardhat verify --network ${hre.network.name} ${contractAddress} ${WORMHOLE_ADDRESS} ${SOLANA_CHAIN_ID}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Deployment failed:", error);
    process.exit(1);
  }); 