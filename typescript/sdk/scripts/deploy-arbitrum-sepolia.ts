import { Wallet } from 'ethers';

import { ProtocolType } from '@hyperlane-xyz/utils';

import { EvmCoreModule } from '../src/core/EvmCoreModule.js';
import { CoreConfig } from '../src/core/types.js';
import { HookType } from '../src/hook/types.js';
import { IsmType } from '../src/ism/types.js';
import { ChainMetadata } from '../src/metadata/chainMetadataTypes.js';
import { MultiProvider } from '../src/providers/MultiProvider.js';

/**
 * Deploy Hyperlane core contracts to Arbitrum Sepolia
 *
 * Usage:
 *   yarn dotenv -e .env -- tsx scripts/deploy-arbitrum-sepolia.ts
 */

async function main() {
  // 1. Get wallet credentials from environment
  const mnemonic = process.env.MNEMONIC;
  const privateKey = process.env.PRIVATE_KEY;

  if (!mnemonic && !privateKey) {
    throw new Error(
      'Either MNEMONIC or PRIVATE_KEY environment variable must be set',
    );
  }

  // 2. Create wallet from mnemonic or private key
  const wallet = mnemonic
    ? Wallet.fromMnemonic(mnemonic)
    : new Wallet(privateKey!);

  console.log(`Deploying with address: ${wallet.address}`);

  // 3. Get configuration from environment
  const rpcUrl =
    process.env.ARBITRUM_SEPOLIA_RPC_URL ||
    'https://sepolia-rollup.arbitrum.io/rpc';
  const ownerAddress = process.env.OWNER_ADDRESS || wallet.address;
  const relayerAddress = process.env.RELAYER_ADDRESS || wallet.address;
  const feeBeneficiary = process.env.FEE_BENEFICIARY || ownerAddress;

  console.log(`\nConfiguration:`);
  console.log(`  Chain: arbitrumsepolia`);
  console.log(`  RPC: ${rpcUrl}`);
  console.log(`  Owner: ${ownerAddress}`);
  console.log(`  Relayer: ${relayerAddress}`);
  console.log(`  Fee Beneficiary: ${feeBeneficiary}`);

  // 4. Define Arbitrum Sepolia chain metadata
  const arbitrumSepoliaMetadata: ChainMetadata = {
    name: 'arbitrumsepolia',
    chainId: 421614,
    domainId: 421614,
    protocol: ProtocolType.Ethereum,
    rpcUrls: [{ http: rpcUrl }],
  };

  // 5. Create MultiProvider with chain metadata
  const multiProvider = new MultiProvider({
    arbitrumsepolia: arbitrumSepoliaMetadata,
  });

  // 6. Set the signer (wallet) for Arbitrum Sepolia
  const provider = multiProvider.getProvider('arbitrumsepolia');
  const connectedWallet = wallet.connect(provider);
  multiProvider.setSigner('arbitrumsepolia', connectedWallet);

  console.log('\nMultiProvider configured');

  // Check wallet balance
  const balance = await connectedWallet.getBalance();
  console.log(
    `Wallet balance: ${balance.toString()} wei (${balance.div(1e9).toNumber() / 1e9} ETH)`,
  );

  if (balance.isZero()) {
    throw new Error(
      'Wallet has no funds! Get Arbitrum Sepolia ETH from https://faucet.quicknode.com/arbitrum/sepolia',
    );
  }

  // 7. Define core deployment config
  const coreConfig: CoreConfig = {
    owner: ownerAddress,
    defaultIsm: {
      type: IsmType.TRUSTED_RELAYER as const,
      relayer: relayerAddress,
    },
    defaultHook: {
      type: HookType.MERKLE_TREE as const,
    },
    requiredHook: {
      type: HookType.PROTOCOL_FEE as const,
      maxProtocolFee: '1000000000000000', // 0.001 ETH
      protocolFee: '0',
      beneficiary: feeBeneficiary,
      owner: ownerAddress,
    },
  };

  console.log('\nDeployment config:');
  console.log(JSON.stringify(coreConfig, null, 2));

  // 8. Deploy core contracts
  console.log('\n🚀 Deploying Hyperlane core contracts to Arbitrum Sepolia...');
  console.log('This may take several minutes...\n');

  const coreModule = await EvmCoreModule.create({
    chain: 'arbitrumsepolia',
    config: coreConfig,
    multiProvider,
  });

  console.log('\n✅ Deployment successful!');
  console.log('\nDeployed addresses:');
  console.log(JSON.stringify(coreModule.serialize(), null, 2));

  // 9. Save deployment addresses
  const fs = await import('fs');
  const path = await import('path');

  const deploymentsDir = './deployments';
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentPath = path.join(
    deploymentsDir,
    `arbitrumsepolia-${Date.now()}.json`,
  );
  const deploymentData = {
    network: 'arbitrumsepolia',
    chainId: 421614,
    deployer: wallet.address,
    timestamp: new Date().toISOString(),
    config: coreConfig,
    addresses: coreModule.serialize(),
  };

  fs.writeFileSync(deploymentPath, JSON.stringify(deploymentData, null, 2));
  console.log(`\n💾 Deployment saved to: ${deploymentPath}`);

  // Also save latest deployment
  const latestPath = path.join(deploymentsDir, `arbitrumsepolia-latest.json`);
  fs.writeFileSync(latestPath, JSON.stringify(deploymentData, null, 2));
  console.log(`💾 Latest deployment: ${latestPath}`);
}

main()
  .then(() => {
    console.log('\n✨ Done!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('❌ Error:', error);
    process.exit(1);
  });
