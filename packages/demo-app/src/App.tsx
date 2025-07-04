import { type IdTokenClaims, LogtoProvider, useLogto, type Prompt } from '@logto/react';
import i18next from 'i18next';
import React, { useCallback, useEffect, useState } from 'react';
import { Helmet } from 'react-helmet';
import { useTranslation } from 'react-i18next';

import '@/scss/normalized.scss';

import styles from './App.module.scss';
import Callback from './Callback';
import DevPanel from './DevPanel';
import congratsDark from './assets/congrats-dark.svg';
import congrats from './assets/congrats.svg';
import { useHandleTokenResponse } from './hooks/use-handle-token-response';
import initI18n from './i18n/init';
import { getLocalData, setLocalData } from './utils';
import {
  initializeKeyPair,
  retrieveAndDecryptSecret,
  clearEncryptionData,
  encryptText,
  decryptText,
} from './utils/encryption';

void initI18n();

// Set up fetch interceptor globally before anything else
(() => {
  const originalFetch = window.fetch;
  const interceptedFetch = async (...args: Parameters<typeof fetch>) => {
    const response = await originalFetch(...args);

    const [url] = args;
    if (typeof url === 'string' && url.includes('/oidc/token')) {
      try {
        const clonedResponse = response.clone();
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const data = await clonedResponse.json();

        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
        if (data.encrypted_client_secret) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
          sessionStorage.setItem('logto_encrypted_client_secret', data.encrypted_client_secret);
        }
      } catch {
        // Silently ignore parsing errors
      }
    }

    return response;
  };
  window.fetch = interceptedFetch;
})();

const Main = () => {
  const config = getLocalData('config');
  const params = new URL(window.location.href).searchParams;
  const { isAuthenticated, isLoading, getIdTokenClaims, getAccessToken, signIn, signOut } =
    useLogto();
  const [user, setUser] = useState<Pick<IdTokenClaims, 'sub' | 'username'>>();
  const [decryptedSecret, setDecryptedSecret] = useState<string | undefined>(undefined);
  const { getEncryptedClientSecret } = useHandleTokenResponse();
  const { t } = useTranslation(undefined, { keyPrefix: 'demo_app' });
  const isInCallback = Boolean(params.get('code'));
  const isDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const [congratsIcon, setCongratsIcon] = useState<string>(isDarkMode ? congratsDark : congrats);
  const [showDevPanel, setShowDevPanel] = useState(getLocalData('ui').showDevPanel ?? false);
  const [showChangePassword, setShowChangePassword] = useState(false);
  const error = params.get('error');
  const errorDescription = params.get('error_description');
  const redirectUri = window.location.origin + window.location.pathname;

  // Text encryption/decryption state
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [encryptMode, setEncryptMode] = useState(true);

  const toggleDevPanel = useCallback(() => {
    setShowDevPanel((previous) => {
      setLocalData('ui', { showDevPanel: !previous });
      return !previous;
    });
  }, []);

  const handleEncryptDecrypt = useCallback(async () => {
    if (!decryptedSecret) {
      setOutputText('Error: No secret available. Please authenticate first.');
      return;
    }

    if (!inputText.trim()) {
      setOutputText('Error: Please enter some text to encrypt/decrypt.');
      return;
    }

    try {
      if (encryptMode) {
        const encrypted = await encryptText(inputText, decryptedSecret);
        setOutputText(encrypted);
      } else {
        const decrypted = await decryptText(inputText, decryptedSecret);
        setOutputText(decrypted);
      }
    } catch (error) {
      setOutputText(`Error: ${error instanceof Error ? error.message : 'Unknown error occurred'}`);
    }
  }, [inputText, decryptedSecret, encryptMode]);

  useEffect(() => {
    if (isInCallback || isLoading || error) {
      return;
    }

    const oneTimeToken = params.get('one_time_token');
    const loginHint = params.get('login_hint');

    const hasMagicLinkParams = Boolean(oneTimeToken && loginHint);

    const loadIdTokenClaims = async () => {
      const userInfo = await getIdTokenClaims();
      setUser(userInfo ?? { sub: 'N/A', username: 'N/A' });
    };

    // If user is authenticated but user info is not loaded yet, load it
    if (isAuthenticated && !user) {
      void loadIdTokenClaims();
    }

    // Retrieve and decrypt the zero-knowledge secret after authentication
    if (isAuthenticated && !decryptedSecret) {
      const retrieveSecret = async () => {
        const secret = await retrieveAndDecryptSecret(getAccessToken, getEncryptedClientSecret);
        if (secret) {
          setDecryptedSecret(secret);
        }
      };
      void retrieveSecret();
    }

    // Initialize key pair and add public key to extra params
    const initializeAndSignIn = async () => {
      const publicKey = await initializeKeyPair();

      const extraParams = Object.fromEntries(
        new URLSearchParams([
          ...new URLSearchParams(config.signInExtraParams).entries(),
          ...new URLSearchParams(window.location.search).entries(),
          ['public_key', publicKey],
        ]).entries()
      );

      await signIn({ redirectUri, extraParams });
    };

    // If user is not authenticated, redirect to sign-in page
    if (!isAuthenticated) {
      void initializeAndSignIn();
    }

    if (isAuthenticated && hasMagicLinkParams) {
      const extraParams = Object.fromEntries(
        new URLSearchParams([
          ...new URLSearchParams(config.signInExtraParams).entries(),
          ...new URLSearchParams(window.location.search).entries(),
        ]).entries()
      );

      void signIn({
        clearTokens: false,
        redirectUri,
        extraParams,
      });
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, [
    params,
    config.signInExtraParams,
    error,
    getIdTokenClaims,
    getAccessToken,
    getEncryptedClientSecret,
    isAuthenticated,
    isInCallback,
    isLoading,
    signIn,
    user,
    decryptedSecret,
    redirectUri,
  ]);

  useEffect(() => {
    const onThemeChange = (event: MediaQueryListEvent) => {
      const isDarkMode = event.matches;
      setCongratsIcon(isDarkMode ? congratsDark : congrats);
    };

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', onThemeChange);

    return () => {
      window
        .matchMedia('(prefers-color-scheme: dark)')
        .removeEventListener('change', onThemeChange);
    };
  }, []);

  if (isInCallback) {
    return <Callback />;
  }

  if (error) {
    return (
      <div className={styles.app}>
        <div className={styles.error}>
          <p>
            Error occurred: {error}
            <br />
            {errorDescription}
          </p>
          <button
            className={styles.button}
            onClick={() => {
              setLocalData('config', {});
              window.location.assign('/demo-app');
            }}
          >
            Reset config and retry
          </button>
        </div>
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    return null;
  }

  // Show change password component if requested
  if (showChangePassword) {
    const ChangePassword = React.lazy(async () => import('./pages/ChangePassword'));
    return (
      <div className={styles.app}>
        <Helmet
          htmlAttributes={{
            lang: i18next.language,
            dir: i18next.dir(),
          }}
        />
        <div style={{ padding: '2rem' }}>
          <button
            style={{
              marginBottom: '1rem',
              padding: '0.5rem 1rem',
              background: 'none',
              border: '1px solid #ccc',
              borderRadius: '4px',
              cursor: 'pointer',
            }}
            onClick={() => {
              setShowChangePassword(false);
            }}
          >
            ← Back to Demo App
          </button>
          <React.Suspense fallback={<div>Loading...</div>}>
            <ChangePassword />
          </React.Suspense>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.app}>
      <Helmet
        htmlAttributes={{
          // We intentionally use the imported i18next instance instead of the hook, since the hook
          // will cause a re-render following some bugs here. This still works for the initial
          // render, so we're good for now. Consider refactoring this in the future.
          lang: i18next.language,
          dir: i18next.dir(),
        }}
      />
      {showDevPanel && <DevPanel />}
      <div className={[styles.card, styles.congrats].join(' ')}>
        {congratsIcon && <img src={congratsIcon} alt="Congrats" />}
        <div className={styles.title}>{t('title')}</div>
        <div className={styles.text}>{t('subtitle')}</div>
        <div className={styles.infoCard}>
          {user.username && (
            <div style={{ textAlign: 'left', marginBottom: '15px' }}>
              <div style={{ fontWeight: 'bold', marginBottom: '5px' }}>{t('username')}</div>
              <pre
                style={{
                  margin: 0,
                  padding: '8px',
                  backgroundColor: 'rgba(255, 255, 255, 0.1)',
                  border: '1px solid rgba(255, 255, 255, 0.2)',
                  borderRadius: '4px',
                  fontSize: '0.9em',
                  fontFamily: 'monospace',
                  overflow: 'auto',
                  maxWidth: '100%',
                  color: 'inherit',
                }}
              >
                {user.username}
              </pre>
            </div>
          )}
          <div style={{ textAlign: 'left', marginBottom: '15px' }}>
            <div style={{ fontWeight: 'bold', marginBottom: '5px' }}>{t('user_id')}</div>
            <pre
              style={{
                margin: 0,
                padding: '8px',
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
                border: '1px solid rgba(255, 255, 255, 0.2)',
                borderRadius: '4px',
                fontSize: '0.9em',
                fontFamily: 'monospace',
                overflow: 'auto',
                maxWidth: '100%',
                color: 'inherit',
              }}
            >
              {user.sub}
            </pre>
          </div>
          {decryptedSecret && (
            <div style={{ textAlign: 'left', marginBottom: '15px' }}>
              <div style={{ fontWeight: 'bold', marginBottom: '5px' }}>Zero-Knowledge Secret:</div>
              <pre
                style={{
                  margin: 0,
                  padding: '8px',
                  backgroundColor: 'rgba(255, 255, 255, 0.1)',
                  border: '1px solid rgba(255, 255, 255, 0.2)',
                  borderRadius: '4px',
                  fontSize: '0.9em',
                  fontFamily: 'monospace',
                  overflow: 'auto',
                  maxWidth: '100%',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  color: 'inherit',
                }}
              >
                {decryptedSecret}
              </pre>
            </div>
          )}
          {!decryptedSecret && (
            <div style={{ textAlign: 'left', marginBottom: '15px' }}>
              <div style={{ fontWeight: 'bold', marginBottom: '5px' }}>Zero-Knowledge Secret:</div>
              <div style={{ fontSize: '0.9em', color: '#666', fontStyle: 'italic' }}>
                Secret retrieval in progress...
              </div>
            </div>
          )}

          {decryptedSecret && (
            <div
              style={{
                borderTop: '1px solid rgba(255, 255, 255, 0.2)',
                paddingTop: '20px',
                marginTop: '20px',
              }}
            >
              <div
                style={{
                  marginBottom: '15px',
                  fontWeight: 'bold',
                  fontSize: '1.1em',
                  textAlign: 'left',
                }}
              >
                Text Encryption Tool
              </div>

              <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
                <button
                  style={{
                    padding: '6px 12px',
                    border: '1px solid rgba(255, 255, 255, 0.3)',
                    borderRadius: '4px',
                    backgroundColor: encryptMode ? '#007bff' : 'rgba(255, 255, 255, 0.1)',
                    color: encryptMode ? 'white' : 'inherit',
                    cursor: 'pointer',
                    fontSize: '0.85em',
                  }}
                  onClick={() => {
                    setEncryptMode(true);
                    setInputText('');
                    setOutputText('');
                  }}
                >
                  Encrypt
                </button>
                <button
                  style={{
                    padding: '6px 12px',
                    border: '1px solid rgba(255, 255, 255, 0.3)',
                    borderRadius: '4px',
                    backgroundColor: encryptMode ? 'rgba(255, 255, 255, 0.1)' : '#007bff',
                    color: encryptMode ? 'inherit' : 'white',
                    cursor: 'pointer',
                    fontSize: '0.85em',
                  }}
                  onClick={() => {
                    setEncryptMode(false);
                    setInputText('');
                    setOutputText('');
                  }}
                >
                  Decrypt
                </button>
              </div>

              <div style={{ marginBottom: '10px' }}>
                <label
                  style={{
                    display: 'block',
                    marginBottom: '5px',
                    fontSize: '0.85em',
                    fontWeight: 'bold',
                  }}
                >
                  {encryptMode ? 'Text to encrypt:' : 'Encrypted text to decrypt:'}
                </label>
                <textarea
                  value={inputText}
                  placeholder={
                    encryptMode ? 'Enter text to encrypt...' : 'Enter encrypted text to decrypt...'
                  }
                  style={{
                    width: '100%',
                    height: '60px',
                    padding: '6px',
                    border: '1px solid rgba(255, 255, 255, 0.3)',
                    borderRadius: '4px',
                    fontSize: '0.85em',
                    fontFamily: 'monospace',
                    backgroundColor: 'rgba(255, 255, 255, 0.1)',
                    color: 'inherit',
                    resize: 'none',
                    boxSizing: 'border-box',
                  }}
                  onChange={(event) => {
                    setInputText(event.target.value);
                  }}
                />
              </div>

              <div style={{ marginBottom: '10px' }}>
                <button
                  disabled={!inputText.trim()}
                  style={{
                    padding: '8px 16px',
                    border: 'none',
                    borderRadius: '4px',
                    backgroundColor: inputText.trim() ? '#28a745' : '#6c757d',
                    color: 'white',
                    cursor: inputText.trim() ? 'pointer' : 'not-allowed',
                    fontSize: '0.85em',
                    fontWeight: 'bold',
                  }}
                  onClick={handleEncryptDecrypt}
                >
                  {encryptMode ? 'Encrypt Text' : 'Decrypt Text'}
                </button>
              </div>

              {outputText && (
                <div>
                  <label
                    style={{
                      display: 'block',
                      marginBottom: '5px',
                      fontSize: '0.85em',
                      fontWeight: 'bold',
                    }}
                  >
                    {encryptMode ? 'Encrypted result:' : 'Decrypted result:'}
                  </label>
                  <textarea
                    readOnly
                    value={outputText}
                    style={{
                      width: '100%',
                      height: '60px',
                      padding: '6px',
                      border: '1px solid rgba(255, 255, 255, 0.3)',
                      borderRadius: '4px',
                      fontSize: '0.85em',
                      fontFamily: 'monospace',
                      backgroundColor: 'rgba(255, 255, 255, 0.05)',
                      color: 'inherit',
                      resize: 'none',
                      boxSizing: 'border-box',
                    }}
                  />
                  <div style={{ marginTop: '5px' }}>
                    <button
                      style={{
                        padding: '4px 8px',
                        border: '1px solid rgba(255, 255, 255, 0.3)',
                        borderRadius: '4px',
                        backgroundColor: 'rgba(255, 255, 255, 0.1)',
                        color: 'inherit',
                        cursor: 'pointer',
                        fontSize: '0.75em',
                      }}
                      onClick={async () => navigator.clipboard.writeText(outputText)}
                    >
                      Copy to Clipboard
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <div
          role="button"
          tabIndex={0}
          className={styles.button}
          onClick={() => {
            setShowChangePassword(true);
          }}
          onKeyDown={({ key }) => {
            if (key === 'Enter' || key === ' ') {
              setShowChangePassword(true);
            }
          }}
        >
          Change Password
        </div>
        <div
          role="button"
          tabIndex={0}
          className={styles.button}
          onClick={async () => {
            clearEncryptionData();
            await signOut(`${window.location.origin}/demo-app`);
          }}
          onKeyDown={({ key }) => {
            if (key === 'Enter' || key === ' ') {
              clearEncryptionData();
              void signOut(`${window.location.origin}/demo-app`);
            }
          }}
        >
          {t('sign_out')}
        </div>
        <div
          role="button"
          tabIndex={0}
          className={styles.button}
          onClick={toggleDevPanel}
          onKeyDown={({ key }) => {
            if (key === 'Enter' || key === ' ') {
              toggleDevPanel();
            }
          }}
        >
          {showDevPanel ? 'Close' : 'Open'} dev panel
        </div>
      </div>
    </div>
  );
};

const App = () => {
  const params = new URL(window.location.href).searchParams;
  const config = getLocalData('config');

  return (
    <LogtoProvider
      config={{
        endpoint: 'http://localhost:3001',
        // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing -- We need to fall back for empty string
        appId: params.get('app_id') || config.appId || '91zok5zm229p3ouzjin1q',
        // eslint-disable-next-line no-restricted-syntax
        prompt: config.prompt ? (config.prompt.split(' ') as Prompt[]) : [],
        scopes: config.scope ? config.scope.split(' ') : [],
        resources: config.resource ? config.resource.split(' ') : [],
      }}
    >
      <Main />
    </LogtoProvider>
  );
};

export default App;
