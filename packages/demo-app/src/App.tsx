import { Prompt, LogtoProvider, useLogto } from '@logto/react';
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
import EncryptionTool from './components/EncryptionTool';
import UserInfoCard from './components/UserInfoCard';
import { useAuthentication } from './hooks/use-authentication';
import initI18n from './i18n/init';
import { getLocalData, setLocalData } from './utils';
import { clearEncryptionData } from './utils/encryption';

void initI18n();

// Helper function to validate prompt values
const isValidPrompt = (value: string): value is Prompt => {
  return value === Prompt.None || value === Prompt.Consent || value === Prompt.Login;
};

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

        if (
          data &&
          typeof data === 'object' &&
          'encrypted_client_secret' in data &&
          data.encrypted_client_secret
        ) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          sessionStorage.setItem('logto_encrypted_client_secret', data.encrypted_client_secret);
        }
      } catch {
        // Silently ignore parsing errors
      }
    }

    return response;
  };

  // eslint-disable-next-line @silverhand/fp/no-mutating-assign
  Object.assign(window, { fetch: interceptedFetch });
})();

const Main = () => {
  const { signOut } = useLogto();
  const { isAuthenticated, isLoading, isInCallback, error, user, decryptedSecret } =
    useAuthentication();
  const { t } = useTranslation(undefined, { keyPrefix: 'demo_app' });
  const params = new URL(window.location.href).searchParams;
  const isDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const [congratsIcon, setCongratsIcon] = useState<string>(isDarkMode ? congratsDark : congrats);
  const [showDevPanel, setShowDevPanel] = useState(getLocalData('ui').showDevPanel ?? false);
  const [showChangePassword, setShowChangePassword] = useState(false);
  const errorDescription = params.get('error_description');

  const toggleDevPanel = useCallback(() => {
    setShowDevPanel((previous) => {
      const newValue = !previous;
      setLocalData('ui', { showDevPanel: newValue });
      return newValue;
    });
  }, []);

  const handleSignOut = useCallback(async () => {
    clearEncryptionData();
    await signOut(`${window.location.origin}/demo-app`);
  }, [signOut]);

  const handleSignOutKeyDown = useCallback(
    ({ key }: React.KeyboardEvent) => {
      if (key === 'Enter' || key === ' ') {
        clearEncryptionData();
        void signOut(`${window.location.origin}/demo-app`);
      }
    },
    [signOut]
  );

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
          lang: i18next.language,
          dir: i18next.dir(),
        }}
      />
      {showDevPanel && <DevPanel />}
      <div className={[styles.card, styles.congrats].join(' ')}>
        {congratsIcon && <img src={congratsIcon} alt="Congrats" />}
        <div className={styles.title}>{t('title')}</div>
        <div className={styles.text}>{t('subtitle')}</div>
        <UserInfoCard user={user} decryptedSecret={decryptedSecret} />
        {decryptedSecret && <EncryptionTool decryptedSecret={decryptedSecret} />}

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
          onClick={handleSignOut}
          onKeyDown={handleSignOutKeyDown}
        >
          {t('sign_out')}
        </div>
        <div
          role="button"
          tabIndex={0}
          className={styles.button}
          onClick={() => {
            toggleDevPanel();
          }}
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
        appId: params.get('app_id') ?? config.appId ?? '91zok5zm229p3ouzjin1q',
        prompt: config.prompt
          ? config.prompt.split(' ').filter((prompt): prompt is Prompt => isValidPrompt(prompt))
          : [],
        scopes: config.scope ? config.scope.split(' ') : [],
        resources: config.resource ? config.resource.split(' ') : [],
      }}
    >
      <Main />
    </LogtoProvider>
  );
};

export default App;
