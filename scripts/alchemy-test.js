const { Network, Alchemy } = require("alchemy-sdk");

async function testAlchemy() {
  const settings = {
    apiKey: process.env.ALCHEMY_API_KEY,
    network: Network.ETH_SEPOLIA,
  };
  
  const alchemy = new Alchemy(settings);
  const block = await alchemy.core.getBlock("latest");
  console.log("Son blok bilgisi:", block);
}

testAlchemy(); 