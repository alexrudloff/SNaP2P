/**
 * Chat command - Interactive chat with a peer
 */

import { Command } from 'commander';
import * as readline from 'node:readline';
import { Peer, WalletManager, formatPrincipal, SNaP2PStream } from 'snap2p';

export const chatCommand = new Command('chat')
  .description('Start an interactive chat session with a peer')
  .argument('<address>', 'Address to connect to (host:port)')
  .option('--testnet', 'Use testnet addresses', false)
  .option('-w, --wallet <name>', 'Use a saved wallet by display name')
  .action(async (address: string, options: { testnet: boolean; wallet?: string }) => {
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

      // Handle connection errors
      connection.multiplexer.on('error', (err) => {
        console.log(`\nConnection error: ${err.message}`);
      });

      connection.session.on('close', () => {
        console.log('\nSession closed');
        process.exit(0);
      });

      // Open a chat stream
      const stream = connection.multiplexer.openStream('chat');
      console.log('Chat stream opened. Type messages and press Enter to send.');
      console.log('Type "quit" or press Ctrl+C to exit.');
      console.log('');

      // Set up readline for user input
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        prompt: 'You: ',
      });

      // Handle incoming messages
      stream.on('data', (data: Buffer) => {
        const text = data.toString('utf8').trim();
        // Clear the current line and print the message
        process.stdout.clearLine(0);
        process.stdout.cursorTo(0);
        console.log(`Peer: ${text}`);
        rl.prompt();
      });

      stream.on('end', async () => {
        console.log('\nPeer disconnected');
        rl.close();
        await peer.close();
        process.exit(0);
      });

      stream.on('error', (err) => {
        console.error('\nStream error:', err.message);
      });

      // Handle user input
      rl.on('line', (line) => {
        const text = line.trim();

        if (text.toLowerCase() === 'quit') {
          stream.end();
          return;
        }

        if (text.length > 0) {
          stream.write(Buffer.from(text + '\n', 'utf8'));
        }

        rl.prompt();
      });

      rl.on('close', async () => {
        console.log('\nClosing connection...');
        stream.end();
        await peer.close();
        process.exit(0);
      });

      // Handle Ctrl+C
      process.on('SIGINT', () => {
        rl.close();
      });

      rl.prompt();

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
