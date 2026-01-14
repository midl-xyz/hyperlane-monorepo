/**
 * Simple Hyperlane Deployment Example
 *
 * This shows how to use the existing EvmCoreModule to deploy to Sepolia.
 * No custom scripts needed - just use the SDK as intended!
 *
 * Usage with private key:
 *   PRIVATE_KEY="0x..." tsx examples/deploy-to-sepolia.ts
 *
 * Usage with mnemonic:
 *   MNEMONIC="your twelve word phrase..." tsx examples/deploy-to-sepolia.ts
 */
import { JsonRpcProvider } from '@ethersproject/providers';
import { Wallet } from 'ethers';

import { EvmCoreModule } from '../src/core/EvmCoreModule.js';
import { HookType } from '../src/hook/types.js';
import { IsmType } from '../src/ism/types.js';
import { MultiProvider } from '../src/providers/MultiProvider.js';

async function deploy() {
  // 1. Setup wallet - supports both private key and mnemonic
  let wallet: Wallet;

  if (process.env.PRIVATE_KEY) {
    console.log('Using PRIVATE_KEY from environment');
    wallet = new Wallet(process.env.PRIVATE_KEY);
  } else if (process.env.MNEMONIC) {
    console.log('Using MNEMONIC from environment');
    wallet = Wallet.fromMnemonic(process.env.MNEMONIC);
  } else {
    console.error(
      '❌ Please set either PRIVATE_KEY or MNEMONIC environment variable',
    );
    console.log('\nExamples:');
    console.log('  export PRIVATE_KEY="0x..."');
    console.log('  OR');
    console.log('  export MNEMONIC="your twelve word seed phrase here"');
    process.exit(1);
  }

  const provider = new JsonRpcProvider(
    'https://ethereum-sepolia.publicnode.com',
  );
  const signer = wallet.connect(provider);

  console.log('Deploying from:', await signer.getAddress());

  // 2. Setup MultiProvider with Sepolia
  const multiProvider = new MultiProvider({
    sepolia: {
      chainId: 11155111,
      domainId: 11155111,
      name: 'sepolia',
      protocol: 'ethereum',
      rpcUrls: [{ http: 'https://ethereum-sepolia.publicnode.com' }],
    },
  });

  multiProvider.setSharedSigner(signer);

  // 3. Deploy using EvmCoreModule.create()
  console.log('Deploying Hyperlane contracts...');

  const evmCoreModule = await EvmCoreModule.create({
    chain: 'sepolia',
    config: {
      owner: await signer.getAddress(),
      defaultIsm: { type: IsmType.TEST_ISM },
      defaultHook: { type: HookType.MERKLE_TREE },
      requiredHook: {
        type: HookType.PROTOCOL_FEE,
        maxProtocolFee: '1000000000000000000',
        protocolFee: '1000000000000000',
        beneficiary: await signer.getAddress(),
        owner: await signer.getAddress(),
      },
    },
    multiProvider,
  });

  // 4. Get addresses
  const addresses = evmCoreModule.serialize();
  console.log('\n✅ Deployed!');
  console.log('Mailbox:', addresses.mailbox);
  console.log('ProxyAdmin:', addresses.proxyAdmin);
  console.log('\nAll addresses:', JSON.stringify(addresses, null, 2));
}

deploy().catch(console.error);
