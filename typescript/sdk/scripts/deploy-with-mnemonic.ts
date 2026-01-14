import { Wallet } from 'ethers';

import { ProtocolType } from '@hyperlane-xyz/utils';

import { EvmCoreModule } from '../src/core/EvmCoreModule.js';
import { CoreConfig } from '../src/core/types.js';
import { HookType } from '../src/hook/types.js';
import { IsmType } from '../src/ism/types.js';
import { ChainMetadata } from '../src/metadata/chainMetadataTypes.js';
import { MultiProvider } from '../src/providers/MultiProvider.js';

/**
 * Deploy Hyperlane core contracts to Sepolia using environment configuration
 *
 * Setup:
 *   1. Copy .env.example to .env
 *   2. Fill in your MNEMONIC or PRIVATE_KEY
 *   3. Optionally configure other settings
 *
 * Usage:
 *   tsx scripts/deploy-with-mnemonic.ts
 *
 * Note: Environment variables are loaded automatically by tsx
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
  const chainName = process.env.DEPLOY_CHAIN || 'sepolia';
  const rpcUrl =
    process.env.SEPOLIA_RPC_URL ||
    'https://ethereum-sepolia-rpc.publicnode.com';
  const ownerAddress = process.env.OWNER_ADDRESS || wallet.address;
  const relayerAddress = process.env.RELAYER_ADDRESS || wallet.address;
  const feeBeneficiary = process.env.FEE_BENEFICIARY || ownerAddress;

  console.log(`\nConfiguration:`);
  console.log(`  Chain: ${chainName}`);
  console.log(`  RPC: ${rpcUrl}`);
  console.log(`  Owner: ${ownerAddress}`);
  console.log(`  Relayer: ${relayerAddress}`);
  console.log(`  Fee Beneficiary: ${feeBeneficiary}`);

  // 4. Define Sepolia chain metadata
  const sepoliaMetadata: ChainMetadata = {
    name: 'sepolia',
    chainId: 11155111,
    domainId: 11155111,
    protocol: ProtocolType.Ethereum,
    rpcUrls: [{ http: rpcUrl }],
  };

  // 5. Create MultiProvider with chain metadata
  const multiProvider = new MultiProvider({
    sepolia: sepoliaMetadata,
  });

  // 6. Set the signer (wallet) for Sepolia
  // This connects the wallet to the Sepolia provider
  const provider = multiProvider.getProvider('sepolia');
  const connectedWallet = wallet.connect(provider);
  multiProvider.setSigner('sepolia', connectedWallet);

  // Alternative: Use shared signer for all chains
  // multiProvider.setSharedSigner(wallet.connect(provider));

  console.log('\nMultiProvider configured');

  // Check wallet balance
  const balance = await connectedWallet.getBalance();
  console.log(
    `Wallet balance: ${balance.toString()} wei (${balance.div(1e9).toNumber() / 1e9} ETH)`,
  );

  if (balance.isZero()) {
    throw new Error(
      'Wallet has no funds! Get Sepolia ETH from https://sepoliafaucet.com/',
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
  console.log('\n🚀 Deploying Hyperlane core contracts to Sepolia...');
  console.log('This may take several minutes...\n');

  const coreModule = await EvmCoreModule.create({
    chain: 'sepolia',
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
    `${chainName}-${Date.now()}.json`,
  );
  const deploymentData = {
    network: chainName,
    chainId: 11155111,
    deployer: wallet.address,
    timestamp: new Date().toISOString(),
    config: coreConfig,
    addresses: coreModule.serialize(),
  };

  fs.writeFileSync(deploymentPath, JSON.stringify(deploymentData, null, 2));
  console.log(`\n💾 Deployment saved to: ${deploymentPath}`);

  // Also save latest deployment
  const latestPath = path.join(deploymentsDir, `${chainName}-latest.json`);
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
