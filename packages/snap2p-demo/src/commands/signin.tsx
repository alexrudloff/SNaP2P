/**
 * Signin command - Interactive Ink-based wallet sign-in
 */

import React from 'react';
import { Command } from 'commander';
import { render } from 'ink';
import { App } from '../components/App.js';

export const signinCommand = new Command('signin')
  .description('Interactive sign-in with Stacks wallet (create, restore, or unlock)')
  .option('--testnet', 'Use testnet addresses', false)
  .action(async (options: { testnet: boolean }) => {
    // Check if we have a TTY (required for Ink)
    if (!process.stdin.isTTY) {
      console.error('Error: signin requires an interactive terminal (TTY).');
      console.error('Run this command directly in a terminal, not piped or in CI.');
      process.exit(1);
    }

    const { waitUntilExit } = render(
      <App
        testnet={options.testnet}
        onReady={(wallet, peer) => {
          // Wallet is ready - in a real app we'd continue to the main interface
          // For now, just show the ready screen
        }}
      />
    );

    await waitUntilExit();
  });
