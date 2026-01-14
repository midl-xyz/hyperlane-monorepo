/**
 * Deploy Hyperlane Core Contracts to Sepolia
 *
 * Usage:
 *   PRIVATE_KEY="0x..." tsx scripts/deploy-sepolia.ts
 *   OR
 *   MNEMONIC="your twelve words..." tsx scripts/deploy-sepolia.ts
 *
 * This script will:
 * 1. Deploy all core Hyperlane contracts to Sepolia
 * 2. Save the deployment addresses to a JSON file
 * 3. Display the addresses for your records
 */
import { JsonRpcProvider } from '@ethersproject/providers';
import { Wallet } from 'ethers';
import { writeFileSync } from 'fs';

import { EvmCoreModule } from '../src/core/EvmCoreModule.js';
import { HookType } from '../src/hook/types.js';
import { IsmType } from '../src/ism/types.js';
import { ChainMetadata } from '../src/metadata/chainMetadataTypes.js';
import { MultiProvider } from '../src/providers/MultiProvider.js';

// Sepolia chain metadata
const sepoliaMetadata: ChainMetadata = {
  chainId: 11155111,
  domainId: 11155111,
  name: 'sepolia',
  protocol: 'ethereum',
  displayName: 'Sepolia',
  nativeToken: {
    name: 'Ether',
    symbol: 'ETH',
    decimals: 18,
  },
  rpcUrls: [
    { http: 'https://ethereum-sepolia.publicnode.com' },
    { http: 'https://gateway.tenderly.co/public/sepolia' },
    { http: 'https://sepolia.drpc.org' },
  ],
  blockExplorers: [
    {
      name: 'Etherscan',
      url: 'https://sepolia.etherscan.io',
      apiUrl: 'https://api-sepolia.etherscan.io/api',
      family: 'etherscan' as const,
    },
  ],
  blocks: {
    confirmations: 1,
    estimateBlockTime: 13,
    reorgPeriod: 2,
  },
  isTestnet: true,
};

async function main() {
  console.log('🚀 Hyperlane Sepolia Deployment Script\n');
  console.log('═'.repeat(60));

  // Step 1: Get wallet from environment
  console.log('\n📋 Step 1: Setting up wallet...');

  let wallet: Wallet;
  const privateKey = process.env.PRIVATE_KEY;
  const mnemonic = process.env.MNEMONIC;

  if (privateKey) {
    console.log('   ✓ Using PRIVATE_KEY from environment');
    wallet = new Wallet(privateKey);
  } else if (mnemonic) {
    console.log('   ✓ Using MNEMONIC from environment');
    wallet = Wallet.fromMnemonic(mnemonic);
  } else {
    console.error(
      '\n❌ Error: No PRIVATE_KEY or MNEMONIC found in environment',
    );
    console.log('\nPlease set one of the following:');
    console.log('  export PRIVATE_KEY="0x..."');
    console.log('  OR');
    console.log('  export MNEMONIC="your twelve words..."');
    process.exit(1);
  }

  const deployerAddress = await wallet.getAddress();
  console.log('   📍 Deployer Address:', deployerAddress);

  // Step 2: Connect to Sepolia
  console.log('\n📋 Step 2: Connecting to Sepolia...');

  const rpcUrl =
    sepoliaMetadata.rpcUrls?.[0]?.http ||
    'https://ethereum-sepolia.publicnode.com';
  const provider = new JsonRpcProvider(rpcUrl);
  const connectedWallet = wallet.connect(provider);

  const balance = await provider.getBalance(deployerAddress);
  const balanceInEth = balance.div('1000000000000000000'); // Simple division for display

  console.log('   ✓ Connected to Sepolia');
  console.log(
    `   💰 Balance: ${balance.toString()} wei (~${balanceInEth.toString()} ETH)`,
  );

  if (balance.isZero()) {
    console.error('\n❌ Error: Deployer has 0 ETH balance');
    console.log('\nPlease fund your address with Sepolia ETH from a faucet:');
    console.log('  - https://www.alchemy.com/faucets/ethereum-sepolia');
    console.log('  - https://sepoliafaucet.com/');
    console.log('  - https://faucet.quicknode.com/ethereum/sepolia');
    process.exit(1);
  }

  // Step 3: Setup MultiProvider
  console.log('\n📋 Step 3: Setting up MultiProvider...');

  const multiProvider = new MultiProvider({
    sepolia: sepoliaMetadata,
  });

  multiProvider.setSharedSigner(connectedWallet);
  console.log('   ✓ MultiProvider configured');

  // Step 4: Define deployment configuration
  console.log('\n📋 Step 4: Preparing deployment configuration...');

  const coreConfig = {
    owner: deployerAddress,
    defaultIsm: {
      type: IsmType.TEST_ISM as const,
    },
    defaultHook: {
      type: HookType.MERKLE_TREE as const,
    },
    requiredHook: {
      type: HookType.PROTOCOL_FEE as const,
      maxProtocolFee: '1000000000000000000', // 1 ETH in wei
      protocolFee: '1000000000000000', // 0.001 ETH in wei
      beneficiary: deployerAddress,
      owner: deployerAddress,
    },
  };

  console.log('   ✓ Configuration:');
  console.log(`     - Owner: ${coreConfig.owner}`);
  console.log(`     - Default ISM: ${coreConfig.defaultIsm.type}`);
  console.log(`     - Default Hook: ${coreConfig.defaultHook.type}`);
  console.log(`     - Required Hook: ${coreConfig.requiredHook.type}`);

  // Step 5: Deploy!
  console.log('\n📋 Step 5: Deploying Hyperlane Core Contracts...');
  console.log('   ⏳ This will take several minutes...\n');

  const startTime = Date.now();

  try {
    const evmCoreModule = await EvmCoreModule.create({
      chain: 'sepolia',
      config: coreConfig,
      multiProvider,
    });

    const deployTime = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`\n   ✅ Deployment completed in ${deployTime}s!`);

    // Step 6: Get deployed addresses
    console.log('\n📋 Step 6: Deployed Contract Addresses:');
    console.log('═'.repeat(60));

    const addresses = evmCoreModule.serialize();

    // Display addresses in a nice format
    const addressEntries = Object.entries(addresses).sort(([a], [b]) =>
      a.localeCompare(b),
    );

    for (const [name, address] of addressEntries) {
      if (address && typeof address === 'string') {
        console.log(`   ${name.padEnd(30)} ${address}`);
      }
    }

    // Step 7: Save to file
    console.log('\n📋 Step 7: Saving deployment artifacts...');

    const deploymentData = {
      network: 'sepolia',
      chainId: 11155111,
      deployer: deployerAddress,
      timestamp: new Date().toISOString(),
      addresses,
      config: coreConfig,
    };

    const filename = `sepolia-deployment-${Date.now()}.json`;
    writeFileSync(filename, JSON.stringify(deploymentData, null, 2));

    console.log(`   ✓ Saved to: ${filename}`);

    // Step 8: Summary and next steps
    console.log('\n' + '═'.repeat(60));
    console.log('✅ DEPLOYMENT SUCCESSFUL!');
    console.log('═'.repeat(60));

    console.log('\n📍 Key Addresses:');
    console.log(`   Mailbox:              ${addresses.mailbox}`);
    console.log(`   ProxyAdmin:           ${addresses.proxyAdmin}`);
    console.log(`   ValidatorAnnounce:    ${addresses.validatorAnnounce}`);
    console.log(`   MerkleTreeHook:       ${addresses.merkleTreeHook}`);
    console.log(
      `   InterchainGasPaymaster: ${addresses.interchainGasPaymaster}`,
    );

    console.log('\n🔗 View on Etherscan:');
    console.log(`   https://sepolia.etherscan.io/address/${addresses.mailbox}`);

    console.log('\n📝 Next Steps:');
    console.log('   1. Verify contracts on Etherscan (optional)');
    console.log('   2. Configure ISM/Hooks if needed');
    console.log('   3. Test sending a message');
    console.log('   4. Try the MIDL integration for updates!');

    console.log('\n🎉 Ready to use your Hyperlane deployment!');
  } catch (error: any) {
    console.error('\n❌ Deployment failed:', error.message);

    if (error.message.includes('insufficient funds')) {
      console.log('\n💡 Tip: You need more Sepolia ETH. Get some from:');
      console.log('   - https://www.alchemy.com/faucets/ethereum-sepolia');
      console.log('   - https://sepoliafaucet.com/');
    } else if (error.message.includes('nonce')) {
      console.log('\n💡 Tip: Try again, there might be a pending transaction.');
    } else {
      console.log('\n💡 Full error:', error);
    }

    process.exit(1);
  }
}

// Run the deployment
main()
  .then(() => {
    console.log('\n👋 Done!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n💥 Unhandled error:', error);
    process.exit(1);
  });
