/**
 * AuthView - Ink-based authentication UI
 *
 * Modeled after hula's AuthView with the same state machine flow.
 */

import React from 'react';
import { Box, Text, useInput } from 'ink';
import SelectInput from 'ink-select-input';
import TextInput from 'ink-text-input';
import type { WalletAccount } from 'snap2p';

/**
 * Auth flow states
 */
export type AuthStep =
  | 'choose'              // Account selector (existing accounts or create/restore)
  | 'delete_choose'       // Delete account selector
  | 'unlock_password'     // Password entry to unlock existing account
  | 'create_show_seed'    // Display generated seed phrase
  | 'set_nick'            // Nickname entry for new wallet
  | 'set_password'        // Password entry for new wallet
  | 'confirm_password'    // Password confirmation for new wallet
  | 'restore_seed'        // Enter recovery seed phrase
  | 'restore_nick'        // Nickname entry for restored wallet
  | 'restore_password'    // Password entry for restored wallet
  | 'restore_confirm';    // Password confirmation for restored wallet

export interface AuthState {
  step: AuthStep;
  identity: WalletAccount | null;
  seedPhrase: string;
  password: string;
  confirmPassword: string;
  nick: string;
  error: string;
}

interface AuthViewProps {
  state: AuthState;
  accounts: WalletAccount[];
  selectedAccountId?: string;
  onChooseMode: (mode: 'create' | 'restore') => void;
  onSeedSaved: () => void;
  onCancelCreate?: () => void;
  onSubmitText: (value: string) => void;
  onSelectAccount?: (accountId: string) => void;
  onBeginDelete?: () => void;
  onDeleteAccount?: (accountId: string) => void;
  onCancel?: () => void;
}

export const AuthView: React.FC<AuthViewProps> = ({
  state,
  accounts,
  selectedAccountId,
  onChooseMode,
  onSeedSaved,
  onCancelCreate,
  onSubmitText,
  onSelectAccount,
  onBeginDelete,
  onDeleteAccount,
  onCancel,
}) => {
  const [inputValue, setInputValue] = React.useState('');

  // Reset input when step changes
  React.useEffect(() => {
    setInputValue('');
  }, [state.step]);

  // Determine if we're showing a select menu vs text input
  const showsSelectInput =
    state.step === 'choose' ||
    state.step === 'delete_choose' ||
    state.step === 'create_show_seed';

  // Handle keyboard shortcuts
  useInput(
    (input, key) => {
      if (key.escape && onCancel) {
        onCancel();
      }
    },
    { isActive: !showsSelectInput }
  );

  // Get placeholder and whether to mask input
  const getInputConfig = (): { placeholder: string; mask: boolean } => {
    switch (state.step) {
      case 'unlock_password':
        return { placeholder: 'Enter password', mask: true };
      case 'set_password':
      case 'restore_password':
        return { placeholder: 'Enter password (min 8 chars)', mask: true };
      case 'confirm_password':
      case 'restore_confirm':
        return { placeholder: 'Confirm password', mask: true };
      case 'set_nick':
      case 'restore_nick':
        return { placeholder: 'Enter display name', mask: false };
      case 'restore_seed':
        return { placeholder: 'Enter 24-word seed phrase', mask: false };
      default:
        return { placeholder: '', mask: false };
    }
  };

  const { placeholder, mask } = getInputConfig();

  // Get title for current step
  const getTitle = (): string => {
    switch (state.step) {
      case 'choose':
        return 'SNaP2P Sign-in';
      case 'delete_choose':
        return 'Delete Identity';
      case 'unlock_password':
        return `Unlock: ${state.identity?.displayName || 'Wallet'}`;
      case 'create_show_seed':
        return 'Save Your Recovery Seed';
      case 'set_nick':
      case 'restore_nick':
        return 'Set Display Name';
      case 'set_password':
      case 'restore_password':
        return 'Set Password';
      case 'confirm_password':
      case 'restore_confirm':
        return 'Confirm Password';
      case 'restore_seed':
        return 'Restore from Seed';
      default:
        return 'Authentication';
    }
  };

  // Get subtitle/instruction for current step
  const getSubtitle = (): string => {
    switch (state.step) {
      case 'choose':
        return accounts.length > 0
          ? 'Select an identity or create a new one'
          : 'Create a new identity to get started';
      case 'delete_choose':
        return 'Select an identity to delete';
      case 'unlock_password':
        return 'Enter your password to unlock (Esc to cancel)';
      case 'create_show_seed':
        return 'Write down these 24 words and keep them safe!';
      case 'set_nick':
      case 'restore_nick':
        return 'Choose a display name for this identity';
      case 'set_password':
      case 'restore_password':
        return 'Choose a password to encrypt your wallet';
      case 'confirm_password':
      case 'restore_confirm':
        return 'Re-enter your password to confirm';
      case 'restore_seed':
        return 'Enter your 24-word recovery phrase';
      default:
        return '';
    }
  };

  const handleSubmit = (value: string) => {
    onSubmitText(value);
    setInputValue('');
  };

  return (
    <Box flexDirection="column" paddingX={1}>
      {/* Header */}
      <Box marginBottom={1}>
        <Text bold color="cyan">
          {getTitle()}
        </Text>
      </Box>

      {/* Subtitle */}
      <Box marginBottom={1}>
        <Text dimColor>{getSubtitle()}</Text>
      </Box>

      {/* Error message */}
      {state.error && (
        <Box marginBottom={1}>
          <Text color="red">{state.error}</Text>
        </Box>
      )}

      {/* Choose step - account selector */}
      {state.step === 'choose' && (
        <SelectInput
          items={[
            ...accounts.map((a) => ({
              label: `${a.displayName} (${a.address.slice(0, 6)}...${a.address.slice(-4)})`,
              value: `acct:${a.id}`,
            })),
            { label: 'Create new identity', value: 'create' },
            { label: 'Restore from seed', value: 'restore' },
            ...(accounts.length > 0
              ? [{ label: 'Delete an identity', value: 'delete' }]
              : []),
          ]}
          onSelect={(item) => {
            if (item.value.startsWith('acct:')) {
              const id = item.value.slice('acct:'.length);
              onSelectAccount?.(id);
            } else if (item.value === 'delete') {
              onBeginDelete?.();
            } else {
              onChooseMode(item.value as 'create' | 'restore');
            }
          }}
        />
      )}

      {/* Delete account selector */}
      {state.step === 'delete_choose' && (
        <SelectInput
          items={[
            ...accounts.map((a) => ({
              label: `${a.displayName} (${a.address.slice(0, 6)}...${a.address.slice(-4)})`,
              value: a.id,
            })),
            { label: 'Cancel', value: 'cancel' },
          ]}
          onSelect={(item) => {
            if (item.value === 'cancel') {
              onCancel?.();
            } else {
              onDeleteAccount?.(item.value);
            }
          }}
        />
      )}

      {/* Show seed phrase step */}
      {state.step === 'create_show_seed' && (
        <Box flexDirection="column">
          <Box marginBottom={1}>
            <Text color="yellow" bold>
              {state.seedPhrase}
            </Text>
          </Box>
          <Text dimColor>Use arrow keys then Enter (Esc to cancel)</Text>
          <Box marginTop={1}>
            <SelectInput
              items={[
                { label: "I've saved it", value: 'ok' },
                { label: 'Cancel', value: 'cancel' },
              ]}
              onSelect={(item) => {
                if (item.value === 'cancel') {
                  onCancelCreate?.();
                } else {
                  onSeedSaved();
                }
              }}
            />
          </Box>
        </Box>
      )}

      {/* Text input steps */}
      {!showsSelectInput && (
        <Box>
          <Text color="cyan">&gt; </Text>
          <TextInput
            value={inputValue}
            onChange={setInputValue}
            onSubmit={handleSubmit}
            placeholder={placeholder}
            mask={mask ? '*' : undefined}
          />
        </Box>
      )}

      {/* Navigation hints */}
      <Box marginTop={1}>
        <Text dimColor>
          {showsSelectInput
            ? 'Use arrow keys to navigate, Enter to select'
            : 'Press Enter to submit, Esc to cancel'}
        </Text>
      </Box>
    </Box>
  );
};

export default AuthView;
