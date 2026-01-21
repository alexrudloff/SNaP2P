/**
 * Main App component for SNaP2P Demo
 *
 * Handles authentication flow and transitions to peer operations.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, useApp, useInput } from 'ink';
import { AuthView, AuthState, AuthStep } from './AuthView.js';
import { WalletManager, WalletAccount, Wallet, Peer, formatPrincipal } from 'snap2p';

type View = 'loading' | 'auth' | 'ready';

interface AppProps {
  testnet?: boolean;
  onReady?: (wallet: Wallet, peer: Peer) => void;
}

export const App: React.FC<AppProps> = ({ testnet = false, onReady }) => {
  const { exit } = useApp();

  const [view, setView] = useState<View>('loading');
  const [walletManager] = useState(() => new WalletManager({ testnet }));
  const [accounts, setAccounts] = useState<WalletAccount[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<string | undefined>();
  const [wallet, setWallet] = useState<Wallet | null>(null);
  const [peer, setPeer] = useState<Peer | null>(null);

  const [auth, setAuth] = useState<AuthState>({
    step: 'choose',
    identity: null,
    seedPhrase: '',
    password: '',
    confirmPassword: '',
    nick: '',
    error: '',
  });

  // Double Ctrl+C to exit
  const [ctrlCCount, setCtrlCCount] = useState(0);
  useInput((input, key) => {
    if (key.ctrl && input === 'c') {
      if (ctrlCCount > 0) {
        exit();
      } else {
        setCtrlCCount(1);
        setTimeout(() => setCtrlCCount(0), 2000);
      }
    }
  });

  // Initialize wallet manager
  useEffect(() => {
    const init = async () => {
      await walletManager.initialize();
      const accts = walletManager.getAccounts();
      setAccounts(accts);
      setView('auth');
    };
    init().catch((err) => {
      setAuth((prev) => ({ ...prev, error: `Init error: ${err.message}` }));
      setView('auth');
    });
  }, [walletManager]);

  // Start peer after wallet is ready
  const startPeer = useCallback(
    async (w: Wallet) => {
      try {
        const p = await Peer.create({ wallet: w, testnet });
        setPeer(p);
        setView('ready');
        onReady?.(w, p);
      } catch (err) {
        setAuth((prev) => ({
          ...prev,
          error: `Failed to create peer: ${err instanceof Error ? err.message : err}`,
        }));
      }
    },
    [testnet, onReady]
  );

  // Handle account selection (for unlock)
  const handleSelectAccount = useCallback(
    (accountId: string) => {
      const account = accounts.find((a) => a.id === accountId);
      if (account) {
        setSelectedAccountId(accountId);
        setAuth((prev) => ({
          ...prev,
          step: 'unlock_password',
          identity: account,
          error: '',
        }));
      }
    },
    [accounts]
  );

  // Handle mode selection (create or restore)
  const handleChooseMode = useCallback((mode: 'create' | 'restore') => {
    if (mode === 'create') {
      // Generate seed phrase
      const seed = walletManager.generateSeedPhrase();
      setAuth((prev) => ({
        ...prev,
        step: 'create_show_seed',
        seedPhrase: seed,
        error: '',
      }));
    } else {
      setAuth((prev) => ({
        ...prev,
        step: 'restore_seed',
        error: '',
      }));
    }
  }, [walletManager]);

  // Handle seed saved confirmation
  const handleSeedSaved = useCallback(() => {
    setAuth((prev) => ({
      ...prev,
      step: 'set_nick',
      error: '',
    }));
  }, []);

  // Handle cancel create
  const handleCancelCreate = useCallback(() => {
    setAuth((prev) => ({
      ...prev,
      step: 'choose',
      seedPhrase: '',
      password: '',
      nick: '',
      error: '',
    }));
  }, []);

  // Handle begin delete
  const handleBeginDelete = useCallback(() => {
    setAuth((prev) => ({
      ...prev,
      step: 'delete_choose',
      error: '',
    }));
  }, []);

  // Handle delete account
  const handleDeleteAccount = useCallback(
    async (accountId: string) => {
      try {
        await walletManager.deleteAccount(accountId);
        const accts = walletManager.getAccounts();
        setAccounts(accts);
        setAuth((prev) => ({
          ...prev,
          step: 'choose',
          error: '',
        }));
      } catch (err) {
        setAuth((prev) => ({
          ...prev,
          error: `Delete failed: ${err instanceof Error ? err.message : err}`,
        }));
      }
    },
    [walletManager]
  );

  // Handle cancel (go back to choose)
  const handleCancel = useCallback(() => {
    setAuth((prev) => ({
      ...prev,
      step: 'choose',
      seedPhrase: '',
      password: '',
      confirmPassword: '',
      nick: '',
      error: '',
    }));
  }, []);

  // Handle text input submission
  const handleSubmitText = useCallback(
    async (value: string) => {
      const step = auth.step;

      try {
        switch (step) {
          case 'unlock_password': {
            if (!selectedAccountId) {
              setAuth((prev) => ({ ...prev, error: 'No account selected' }));
              return;
            }
            const w = await walletManager.unlock(selectedAccountId, value);
            setWallet(w);
            await startPeer(w);
            break;
          }

          case 'set_nick': {
            if (!value.trim()) {
              setAuth((prev) => ({ ...prev, error: 'Display name is required' }));
              return;
            }
            setAuth((prev) => ({
              ...prev,
              nick: value.trim(),
              step: 'set_password',
              error: '',
            }));
            break;
          }

          case 'set_password': {
            if (value.length < 8) {
              setAuth((prev) => ({
                ...prev,
                error: 'Password must be at least 8 characters',
              }));
              return;
            }
            setAuth((prev) => ({
              ...prev,
              password: value,
              step: 'confirm_password',
              error: '',
            }));
            break;
          }

          case 'confirm_password': {
            if (value !== auth.password) {
              setAuth((prev) => ({ ...prev, error: 'Passwords do not match' }));
              return;
            }
            // Create wallet
            const account = await walletManager.createWallet(
              auth.seedPhrase,
              auth.password,
              auth.nick
            );
            const accts = walletManager.getAccounts();
            setAccounts(accts);
            const w = walletManager.getWallet();
            setWallet(w);
            setAuth((prev) => ({
              ...prev,
              identity: account,
              seedPhrase: '',
              password: '',
              confirmPassword: '',
              error: '',
            }));
            await startPeer(w);
            break;
          }

          case 'restore_seed': {
            if (!value.trim()) {
              setAuth((prev) => ({ ...prev, error: 'Seed phrase is required' }));
              return;
            }
            setAuth((prev) => ({
              ...prev,
              seedPhrase: value.trim(),
              step: 'restore_nick',
              error: '',
            }));
            break;
          }

          case 'restore_nick': {
            if (!value.trim()) {
              setAuth((prev) => ({ ...prev, error: 'Display name is required' }));
              return;
            }
            setAuth((prev) => ({
              ...prev,
              nick: value.trim(),
              step: 'restore_password',
              error: '',
            }));
            break;
          }

          case 'restore_password': {
            if (value.length < 8) {
              setAuth((prev) => ({
                ...prev,
                error: 'Password must be at least 8 characters',
              }));
              return;
            }
            setAuth((prev) => ({
              ...prev,
              password: value,
              step: 'restore_confirm',
              error: '',
            }));
            break;
          }

          case 'restore_confirm': {
            if (value !== auth.password) {
              setAuth((prev) => ({ ...prev, error: 'Passwords do not match' }));
              return;
            }
            // Restore wallet
            const account = await walletManager.createWallet(
              auth.seedPhrase,
              auth.password,
              auth.nick
            );
            const accts = walletManager.getAccounts();
            setAccounts(accts);
            const w = walletManager.getWallet();
            setWallet(w);
            setAuth((prev) => ({
              ...prev,
              identity: account,
              seedPhrase: '',
              password: '',
              confirmPassword: '',
              error: '',
            }));
            await startPeer(w);
            break;
          }
        }
      } catch (err) {
        setAuth((prev) => ({
          ...prev,
          error: err instanceof Error ? err.message : String(err),
        }));
      }
    },
    [auth, selectedAccountId, walletManager, startPeer]
  );

  // Loading view
  if (view === 'loading') {
    return (
      <Box>
        <Text>Loading...</Text>
      </Box>
    );
  }

  // Auth view
  if (view === 'auth') {
    return (
      <Box flexDirection="column" borderStyle="round" borderColor="cyan" padding={1}>
        <AuthView
          state={auth}
          accounts={accounts}
          selectedAccountId={selectedAccountId}
          onChooseMode={handleChooseMode}
          onSeedSaved={handleSeedSaved}
          onCancelCreate={handleCancelCreate}
          onSubmitText={handleSubmitText}
          onSelectAccount={handleSelectAccount}
          onBeginDelete={handleBeginDelete}
          onDeleteAccount={handleDeleteAccount}
          onCancel={handleCancel}
        />
      </Box>
    );
  }

  // Ready view (peer is active)
  return (
    <Box flexDirection="column" borderStyle="round" borderColor="green" padding={1}>
      <Text bold color="green">
        Ready!
      </Text>
      <Box marginTop={1}>
        <Text>
          Principal: <Text color="cyan">{wallet ? formatPrincipal(wallet.principal) : 'N/A'}</Text>
        </Text>
      </Box>
      <Box marginTop={1}>
        <Text dimColor>Press Ctrl+C twice to exit</Text>
      </Box>
    </Box>
  );
};

export default App;
