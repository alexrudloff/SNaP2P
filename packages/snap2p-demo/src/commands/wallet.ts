/**
 * Wallet management commands
 */

import { Command } from 'commander';
import * as readline from 'node:readline';
import { WalletManager } from 'snap2p';

export const walletCommand = new Command('wallet')
  .description('Manage wallets');

walletCommand
  .command('create')
  .description('Create a new wallet')
  .option('--testnet', 'Use testnet', false)
  .action(async (options: { testnet: boolean }) => {
    const manager = new WalletManager({ testnet: options.testnet });
    await manager.initialize();

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const question = (prompt: string): Promise<string> => {
      return new Promise((resolve) => {
        rl.question(prompt, resolve);
      });
    };

    const questionHidden = (prompt: string): Promise<string> => {
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
    };

    try {
      // Generate seed phrase
      const seedPhrase = manager.generateSeedPhrase();
      console.log('\nGenerated seed phrase (SAVE THIS SECURELY):\n');
      console.log(`  ${seedPhrase}\n`);

      const confirmed = await question('Have you saved your seed phrase? (yes/no): ');
      if (confirmed.toLowerCase() !== 'yes') {
        console.log('Aborted. Please save your seed phrase before continuing.');
        rl.close();
        return;
      }

      const displayName = await question('Enter a display name: ');
      if (!displayName.trim()) {
        console.log('Display name is required.');
        rl.close();
        return;
      }

      const password = await questionHidden('Enter password (min 8 chars): ');
      if (password.length < 8) {
        console.log('Password must be at least 8 characters.');
        rl.close();
        return;
      }

      const confirmPassword = await questionHidden('Confirm password: ');
      if (password !== confirmPassword) {
        console.log('Passwords do not match.');
        rl.close();
        return;
      }

      const account = await manager.createWallet(seedPhrase, password, displayName.trim());
      console.log(`\nWallet created successfully!`);
      console.log(`  Address: ${account.address}`);
      console.log(`  Display Name: ${account.displayName}`);
    } finally {
      rl.close();
    }
  });

walletCommand
  .command('restore')
  .description('Restore a wallet from seed phrase')
  .option('--testnet', 'Use testnet', false)
  .action(async (options: { testnet: boolean }) => {
    const manager = new WalletManager({ testnet: options.testnet });
    await manager.initialize();

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const question = (prompt: string): Promise<string> => {
      return new Promise((resolve) => {
        rl.question(prompt, resolve);
      });
    };

    const questionHidden = (prompt: string): Promise<string> => {
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
    };

    try {
      const seedPhrase = await question('Enter seed phrase: ');
      if (!seedPhrase.trim()) {
        console.log('Seed phrase is required.');
        rl.close();
        return;
      }

      const displayName = await question('Enter a display name: ');
      if (!displayName.trim()) {
        console.log('Display name is required.');
        rl.close();
        return;
      }

      const password = await questionHidden('Enter password (min 8 chars): ');
      if (password.length < 8) {
        console.log('Password must be at least 8 characters.');
        rl.close();
        return;
      }

      const confirmPassword = await questionHidden('Confirm password: ');
      if (password !== confirmPassword) {
        console.log('Passwords do not match.');
        rl.close();
        return;
      }

      const account = await manager.createWallet(seedPhrase.trim(), password, displayName.trim());
      console.log(`\nWallet restored successfully!`);
      console.log(`  Address: ${account.address}`);
      console.log(`  Display Name: ${account.displayName}`);
    } finally {
      rl.close();
    }
  });

walletCommand
  .command('list')
  .description('List all wallets')
  .option('--testnet', 'Use testnet', false)
  .action(async (options: { testnet: boolean }) => {
    const manager = new WalletManager({ testnet: options.testnet });
    await manager.initialize();

    const accounts = manager.getAccounts();
    const currentId = manager.getCurrentAccountId();

    if (accounts.length === 0) {
      console.log('No wallets found. Use "wallet create" to create one.');
      return;
    }

    console.log('\nWallets:\n');
    for (const account of accounts) {
      const current = account.id === currentId ? ' (current)' : '';
      console.log(`  ${account.displayName}${current}`);
      console.log(`    Address: ${account.address}`);
      console.log(`    Created: ${account.createdAt}`);
      console.log('');
    }
  });

walletCommand
  .command('delete <name>')
  .description('Delete a wallet by display name')
  .option('--testnet', 'Use testnet', false)
  .action(async (name: string, options: { testnet: boolean }) => {
    const manager = new WalletManager({ testnet: options.testnet });
    await manager.initialize();

    const accounts = manager.getAccounts();
    const account = accounts.find(a => a.displayName === name);

    if (!account) {
      console.log(`Wallet "${name}" not found.`);
      return;
    }

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const answer = await new Promise<string>((resolve) => {
      rl.question(`Are you sure you want to delete wallet "${name}"? (yes/no): `, resolve);
    });
    rl.close();

    if (answer.toLowerCase() !== 'yes') {
      console.log('Aborted.');
      return;
    }

    await manager.deleteAccount(account.id);
    console.log(`Wallet "${name}" deleted.`);
  });
