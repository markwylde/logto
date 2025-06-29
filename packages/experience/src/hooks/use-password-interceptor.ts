/**
 * Hook to intercept password input and handle zero-knowledge encryption.
 * This hook manages password splitting and temporary storage of the client password.
 */

import { useCallback, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';

import { storeUserEncryptedSecret, storeSessionEncryptedSecret } from '@/utils/zero-knowledge-api';
import {
  splitPassword,
  generateSecret,
  encryptWithPassword,
  decryptWithPassword,
  encryptWithPublicKey,
  deriveAppSecret,
} from '@/utils/zero-knowledge-encryption';

export type PasswordInterceptorResult = {
  processPassword: (password: string) => Promise<string>;
  handleSecretManagement: (
    verificationId: string,
    encryptedSecret: string | undefined
  ) => Promise<void>;
};

const usePasswordInterceptor = (): PasswordInterceptorResult => {
  const [searchParams] = useSearchParams();
  const clientPasswordRef = useRef<string | undefined>(null);
  const publicKeyRef = useRef<string | undefined>(searchParams.get('public_key'));

  /**
   * Process the password by splitting it into server and client parts.
   * Returns the server password for authentication.
   */
  const processPassword = useCallback(async (password: string): Promise<string> => {
    const { serverPassword, clientPassword } = await splitPassword(password);

    // Store client password temporarily for secret encryption/decryption
    clientPasswordRef.current = clientPassword;

    return serverPassword;
  }, []);

  /**
   * Handle secret management after successful authentication.
   * Creates a new secret if none exists, or decrypts existing secret.
   * Then derives an app-specific secret and encrypts it with the app's public key for the session.
   */
  const handleSecretManagement = useCallback(
    async (verificationId: string, encryptedSecret: string | undefined) => {
      const clientPassword = clientPasswordRef.current;
      const publicKey = publicKeyRef.current;

      // Get app ID from session storage (set during OAuth flow)
      const appId = sessionStorage.getItem('app_id');

      if (!clientPassword) {
        throw new Error('Client password not available');
      }

      if (!publicKey) {
        // No public key provided, skip secret management
        return;
      }

      if (!appId) {
        // No app ID available, skip secret management
        return;
      }

      let baseSecret: string;

      if (encryptedSecret) {
        // Subsequent login - decrypt existing secret
        try {
          baseSecret = await decryptWithPassword(encryptedSecret, clientPassword);
        } catch {
          // Failed to decrypt - likely password was reset by admin
          // Generate new secret and re-encrypt with current password
          baseSecret = generateSecret();
          const newEncryptedSecret = await encryptWithPassword(baseSecret, clientPassword);
          await storeUserEncryptedSecret(newEncryptedSecret);
        }
      } else {
        // First login - generate and store new secret
        baseSecret = generateSecret();
        const newEncryptedSecret = await encryptWithPassword(baseSecret, clientPassword);
        await storeUserEncryptedSecret(newEncryptedSecret);
      }

      // Derive app-specific secret from base secret
      const appSpecificSecret = await deriveAppSecret(baseSecret, appId);
      // Encrypt app-specific secret with app's public key for this session
      const encryptedClientSecret = await encryptWithPublicKey(appSpecificSecret, publicKey);
      await storeSessionEncryptedSecret(encryptedClientSecret);

      // Clear the client password from memory
      clientPasswordRef.current = null;
    },
    []
  );

  return {
    processPassword,
    handleSecretManagement,
  };
};

export default usePasswordInterceptor;
