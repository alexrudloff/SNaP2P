/**
 * Dial command - Connect to a peer and send a message
 */

import { Command } from 'commander';
import { Peer, WalletManager, formatPrincipal } from 'snap2p';

export const dialCommand = new Command('dial')
  .description('Connect to a peer and send a single message')
  .argument('<address>', 'Address to connect to (host:port)')
  .option('-m, --message <message>', 'Message to send', 'Hello from SNaP2P!')
  .option('--testnet', 'Use testnet addresses', false)
  .option('-w, --wallet <name>', 'Use a saved wallet by display name')
  .action(async (address: string, options: { message: string; testnet: boolean; wallet?: string }) => {
    let peer: Peer;

    if (options.wallet) {
      // Use persistent wallet
      const manager = new WalletManager({ testnet: options.testnet });
      await manager.initialize();

      const accounts = manager.getAccounts();
      const account = accounts.find(a => a.displayName === options.wallet);

      if (!account) {
        console.error(`Wallet "${options.wallet}" not found. Use "wallet list" to see available wallets.`);
        process.exit(1);
      }

      // Prompt for password
      const password = await promptPassword('Enter wallet password: ');

      try {
        const wallet = await manager.unlock(account.id, password);
        console.log(`Unlocked wallet: ${account.displayName}`);
        peer = await Peer.create({ wallet, testnet: options.testnet });
      } catch (err) {
        console.error('Failed to unlock wallet:', err instanceof Error ? err.message : err);
        process.exit(1);
      }
    } else {
      // Use ephemeral wallet
      console.log('Creating peer with ephemeral wallet...');
      peer = await Peer.create({ testnet: options.testnet });
    }

    console.log(`Local principal: ${formatPrincipal(peer.principal)}`);
    console.log('');

    try {
      console.log(`Connecting to ${address}...`);
      const connection = await peer.dial(address);

      console.log(`Connected to: ${formatPrincipal(connection.remotePrincipal)}`);
      console.log('');

      // Open a stream and send message
      const stream = connection.multiplexer.openStream('message');
      console.log(`Opened stream ${stream.streamId}`);

      // Set up response handler
      stream.on('data', (data: Buffer) => {
        const text = data.toString('utf8');
        console.log(`Received response: ${text}`);

        // Close after receiving response
        stream.end();
      });

      stream.on('end', async () => {
        console.log('Stream ended');
        await peer.close();
        process.exit(0);
      });

      stream.on('error', (err) => {
        console.error('Stream error:', err.message);
      });

      // Send the message
      console.log(`Sending: ${options.message}`);
      stream.write(Buffer.from(options.message, 'utf8'));

      // Handle timeout
      setTimeout(async () => {
        console.log('Timeout waiting for response');
        await peer.close();
        process.exit(1);
      }, 10000);

    } catch (err) {
      console.error('Connection failed:', err instanceof Error ? err.message : err);
      await peer.close();
      process.exit(1);
    }
  });

function promptPassword(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode?.(true);
    stdin.resume();

    let password = '';
    const onData = (ch: Buffer) => {
      const c = ch.toString();
      if (c === '\n' || c === '\r') {
        stdin.setRawMode?.(wasRaw);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(password);
      } else if (c === '\u0003') {
        process.exit();
      } else if (c === '\u007f') {
        password = password.slice(0, -1);
      } else {
        password += c;
      }
    };
    stdin.on('data', onData);
  });
}
