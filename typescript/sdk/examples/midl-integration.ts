// /**
//  * Example: Using MIDL to update Hyperlane Core contracts
//  *
//  * This example demonstrates how to use the MIDL integration to:
//  * 1. Queue Hyperlane contract update transactions
//  * 2. Bundle them with a Bitcoin transaction
//  * 3. Broadcast everything atomically via MIDL
//  */

// import { EvmCoreModule } from './src/core/EvmCoreModuleMidl.js';
// import { MultiProvider } from './src/providers/MultiProvider.js';
// import { createConfig, AddressType, connect, getDefaultAccount, AddressPurpose } from '@midl/core';
// import { keyPairConnector } from '@midl/connectors';
// import { regtest, getEVMAddress } from '@midl/executor';
// import { createWalletClient, createPublicClient, http } from 'viem';
// import { midlRegtest } from '@midl/executor';

// /**
//  * Initialize MIDL configuration
//  */
// function initializeMidlConfig() {
//   if (!process.env.MNEMONIC) {
//     throw new Error('MNEMONIC environment variable is required');
//   }

//   return createConfig({
//     networks: [regtest],
//     connectors: [
//       keyPairConnector({
//         mnemonic: process.env.MNEMONIC,
//         paymentAddressType: AddressType.P2WPKH,
//       }),
//     ],
//   });
// }

// /**
//  * Create MIDL wallet and public clients
//  */
// function createMidlClients(midlConfig: any) {
//   const defaultAccount = getDefaultAccount(midlConfig);
//   const evmAddress = getEVMAddress(defaultAccount, regtest);

//   const walletClient = createWalletClient({
//     chain: midlRegtest,
//     transport: http(midlRegtest.rpcUrls.default.http[0]),
//     account: evmAddress as `0x${string}`,
//   });

//   const publicClient = createPublicClient({
//     chain: midlRegtest,
//     transport: http(),
//   });

//   return { walletClient, publicClient, evmAddress };
// }

// /**
//  * Main example function
//  */
// async function main() {
//   try {
//     console.log('🚀 Hyperlane + MIDL Integration Example\n');

//     // Step 1: Initialize MIDL
//     console.log('1️⃣  Initializing MIDL configuration...');
//     const midlConfig = initializeMidlConfig();

//     // Step 2: Connect to MIDL network
//     console.log('2️⃣  Connecting to MIDL network...');
//     await connect(midlConfig, {
//       purposes: [AddressPurpose.Payment, AddressPurpose.Ordinals],
//     });

//     const defaultAccount = getDefaultAccount(midlConfig);
//     console.log('   ✓ Connected with BTC address:', defaultAccount.address);

//     // Step 3: Create MIDL clients
//     console.log('3️⃣  Creating MIDL clients...');
//     const { walletClient, publicClient, evmAddress } = createMidlClients(midlConfig);
//     console.log('   ✓ EVM address:', evmAddress);

//     // Step 4: Initialize MultiProvider (you'll need to configure this for your chains)
//     console.log('4️⃣  Initializing MultiProvider...');
//     // const multiProvider = new MultiProvider({
//     //   sepolia: { /* chain config */ },
//     //   // ... other chains
//     // });

//     // For this example, we'll show the structure
//     console.log('   ⚠️  Note: Configure MultiProvider with your chain metadata');

//     // Step 5: Create EvmCoreModule with MIDL support
//     console.log('5️⃣  Creating EvmCoreModule with MIDL integration...');

//     // Example configuration (replace with your actual values)
//     const coreModuleParams = {
//       chain: 'sepolia',
//       config: {
//         owner: evmAddress,
//         defaultIsm: {
//           type: 'trustedRelayerIsm',
//           relayer: evmAddress,
//         },
//         defaultHook: {
//           type: 'merkleTreeHook',
//         },
//         requiredHook: {
//           type: 'protocolFee',
//           beneficiary: evmAddress,
//           maxProtocolFee: '1000000000000000', // 0.001 ETH
//           protocolFee: '100000000000000',     // 0.0001 ETH
//         },
//       },
//       addresses: {
//         mailbox: '0x...', // Your deployed mailbox address
//         proxyAdmin: '0x...', // Your proxy admin address
//         // ... other addresses
//       },
//     };

//     // const coreModule = new EvmCoreModule(
//     //   multiProvider,
//     //   coreModuleParams,
//     //   {
//     //     config: midlConfig,
//     //     btcAddress: defaultAccount.address,
//     //   }
//     // );

//     console.log('   ✓ EvmCoreModule created with MIDL support');

//     // Step 6: Queue update transactions
//     console.log('6️⃣  Queueing update transactions...');

//     // Example: Update configuration
//     // const updatedConfig = {
//     //   ...coreModuleParams.config,
//     //   defaultIsm: {
//     //     type: 'multisigIsm',
//     //     validators: ['0x...', '0x...'],
//     //     threshold: 2,
//     //   },
//     // };

//     // await coreModule.queueUpdateTransactions(updatedConfig);
//     // const intentionCount = coreModule.getMidlIntentionCount();
//     // console.log(`   ✓ Queued ${intentionCount} transaction intentions`);

//     console.log('   ⚠️  Note: Uncomment to queue actual transactions');

//     // Step 7: Broadcast via MIDL
//     console.log('7️⃣  Broadcasting transactions via MIDL...');

//     // const result = await coreModule.broadcastMidlTransactions(
//     //   walletClient,
//     //   publicClient
//     // );

//     // console.log('   ✓ Broadcast complete!');
//     // console.log('   📍 BTC Transaction ID:', result.btcTxId);
//     // console.log('   📍 EVM Transactions:', result.evmTransactions.length);

//     console.log('   ⚠️  Note: Uncomment to broadcast actual transactions');

//     console.log('\n✅ Example completed successfully!');
//     console.log('\nNext steps:');
//     console.log('1. Configure your MultiProvider with real chain metadata');
//     console.log('2. Deploy Hyperlane core contracts and get addresses');
//     console.log('3. Uncomment the transaction queueing and broadcasting code');
//     console.log('4. Run the script with: MNEMONIC="your mnemonic" tsx examples/midl-integration.ts');

//   } catch (error) {
//     console.error('❌ Error:', error);
//     process.exit(1);
//   }
// }

// // Alternative: Manual transaction encoding example
// async function manualTransactionExample() {
//   console.log('\n📝 Manual Transaction Encoding Example\n');

//   const midlConfig = initializeMidlConfig();
//   await connect(midlConfig, {
//     purposes: [AddressPurpose.Payment, AddressPurpose.Ordinals],
//   });

//   const { walletClient, publicClient } = createMidlClients(midlConfig);

//   // Example: Manually encoding a transaction
//   const { encodeFunctionData } = await import('viem');
//   const { addTxIntention, finalizeBTCTransaction, signIntention } = await import('@midl/executor');

//   // Example contract ABI (Mailbox.setDefaultIsm)
//   const mailboxAbi = [
//     {
//       name: 'setDefaultIsm',
//       type: 'function',
//       inputs: [{ name: 'module', type: 'address' }],
//       outputs: [],
//       stateMutability: 'nonpayable',
//     },
//   ];

//   // Encode the function call
//   const data = encodeFunctionData({
//     abi: mailboxAbi,
//     functionName: 'setDefaultIsm',
//     args: ['0x1234567890123456789012345678901234567890'],
//   });

//   console.log('Encoded transaction data:', data);

//   // Add transaction intention
//   const intention = await addTxIntention(midlConfig, {
//     evmTransaction: {
//       to: '0xMailboxAddress' as `0x${string}`,
//       data: data,
//     },
//   });

//   console.log('Transaction intention created:', intention);
//   console.log('\n✓ Manual encoding example complete');
// }

// // Run the example
// if (require.main === module) {
//   main()
//     .then(() => {
//       console.log('\n👋 Example finished');
//       process.exit(0);
//     })
//     .catch((error) => {
//       console.error('Unhandled error:', error);
//       process.exit(1);
//     });
// }

// export { main, manualTransactionExample };
