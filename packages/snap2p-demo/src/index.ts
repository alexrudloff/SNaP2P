#!/usr/bin/env node
/**
 * SNaP2P Demo CLI
 */

import { Command } from 'commander';
import { listenCommand } from './commands/listen.js';
import { dialCommand } from './commands/dial.js';
import { chatCommand } from './commands/chat.js';
import { walletCommand } from './commands/wallet.js';
import { signinCommand } from './commands/signin.js';

const program = new Command();

program
  .name('snap2p-demo')
  .description('SNaP2P Demo CLI - Stacks-Native P2P Session & Stream Framework')
  .version('0.1.0');

program.addCommand(signinCommand);
program.addCommand(walletCommand);
program.addCommand(listenCommand);
program.addCommand(dialCommand);
program.addCommand(chatCommand);

program.parse();
