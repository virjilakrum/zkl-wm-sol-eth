async function main() {
  const [deployer] = await ethers.getSigners();
  
  // Program ID ve Emitter PDA hesaplama
  const { PublicKey } = require("@solana/web3.js");
  const programId = new PublicKey('YOUR_PROGRAM_ID');
  const [emitterPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("emitter")],
    programId
  );

  // Ethereum için emitter adresi hazırlama
  let SOLANA_EMITTER = ethers.utils.hexZeroPad(
    `0x${emitterPda.toBuffer().toString('hex')}`,
    32
  );

  const CrossChainMessaging = await ethers.getContractFactory("CrossChainMessaging");
  const crossChain = await CrossChainMessaging.deploy(
    "0x13e4577cef5f7da8519d69aa86e4c879ba85abd9", // Wormhole
    1, // Solana Chain ID
    SOLANA_EMITTER
  );

  await crossChain.deployed();
  console.log("Contract deployed to:", crossChain.address);
} 