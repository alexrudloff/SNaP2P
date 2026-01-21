/**
 * Listen command - Start an echo server
 */

import { Command } from 'commander';
import * as readline from 'node:readline';
import { Peer, WalletManager, formatPrincipal, SNaP2PStream } from 'snap2p';

export const listenCommand = new Command('listen')
  .description('Start an echo server that echoes back received messages')
  .argument('<port>', 'Port to listen on')
  .option('-h, --host <host>', 'Host to bind to', '127.0.0.1')
  .option('--testnet', 'Use testnet addresses', false)
  .option('-w, --wallet <name>', 'Use a saved wallet by display name')
  .action(async (port: string, options: { host: string; testnet: boolean; wallet?: string }) => {
    const portNum = parseInt(port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      console.error('Invalid port number');
      process.exit(1);
    }

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

    peer.on('connection', (info) => {
      console.log(`New connection from: ${formatPrincipal(info.remotePrincipal)}`);

      // Handle multiplexer errors gracefully
      info.multiplexer.on('error', (err) => {
        console.log(`  Connection error: ${err.message}`);
      });

      // Set up stream handler for echo
      info.multiplexer.on('stream', (stream: SNaP2PStream) => {
        console.log(`  Stream ${stream.streamId} opened${stream.label ? ` (${stream.label})` : ''}`);

        // Echo back all received data
        stream.on('data', (data: Buffer) => {
          const text = data.toString('utf8');
          console.log(`  [${stream.streamId}] Received: ${text}`);
          stream.write(data);
        });

        stream.on('end', () => {
          console.log(`  Stream ${stream.streamId} ended`);
        });

        stream.on('error', (err) => {
          console.error(`  Stream ${stream.streamId} error:`, err.message);
        });
      });

      info.session.on('close', () => {
        console.log(`Connection closed: ${formatPrincipal(info.remotePrincipal)}`);
      });
    });

    peer.on('error', (err) => {
      console.error('Peer error:', err.message);
    });

    try {
      const locator = await peer.listen(portNum, options.host);
      console.log(`Listening on ${locator.host}:${locator.port}`);
      console.log('Waiting for connections... (Ctrl+C to stop)');
      console.log('');

      // Handle graceful shutdown
      process.on('SIGINT', async () => {
        console.log('\nShutting down...');
        await peer.close();
        process.exit(0);
      });
    } catch (err) {
      console.error('Failed to start listener:', err instanceof Error ? err.message : err);
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
