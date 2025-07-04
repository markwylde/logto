import { type IdTokenClaims, useLogto } from '@logto/react';
import { useEffect, useState } from 'react';

import { getLocalData } from '../utils';
import { initializeKeyPair, retrieveAndDecryptSecret } from '../utils/encryption';

import { useHandleTokenResponse } from './use-handle-token-response';

export const useAuthentication = () => {
  const config = getLocalData('config');
  const params = new URL(window.location.href).searchParams;
  const { isAuthenticated, isLoading, getIdTokenClaims, getAccessToken, signIn } = useLogto();
  const [user, setUser] = useState<Pick<IdTokenClaims, 'sub' | 'username'>>();
  const [decryptedSecret, setDecryptedSecret] = useState<string | undefined>();
  const { getEncryptedClientSecret } = useHandleTokenResponse();

  const isInCallback = Boolean(params.get('code'));
  const error = params.get('error');
  const redirectUri = window.location.origin + window.location.pathname;

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

    const retrieveSecret = async () => {
      const secret = await retrieveAndDecryptSecret(
        getAccessToken,
        () => getEncryptedClientSecret() ?? undefined
      );
      if (secret) {
        setDecryptedSecret(secret);
      }
    };

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

    if (isAuthenticated && !user) {
      void loadIdTokenClaims();
    }

    if (isAuthenticated && !decryptedSecret) {
      void retrieveSecret();
    }

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

  return {
    isAuthenticated,
    isLoading,
    isInCallback,
    error,
    user,
    decryptedSecret,
  };
};
