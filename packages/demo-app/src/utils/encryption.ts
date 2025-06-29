/**
 * Encryption utilities for the demo app's zero-knowledge encryption implementation.
 * These utilities handle key pair generation and secret decryption.
 */

/**
 * Generate an RSA key pair for asymmetric encryption.
 */
export async function generateKeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );

  // Export keys to JWK format
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  return {
    publicKey: JSON.stringify(publicKeyJwk),
    privateKey: JSON.stringify(privateKeyJwk),
  };
}

/**
 * Decrypt data with an RSA private key.
 */
export async function decryptWithPrivateKey(
  encryptedData: string,
  privateKeyJwk: string
): Promise<string> {
  const decoder = new TextDecoder();

  // Decode from base64
  const encrypted = Uint8Array.from(atob(encryptedData), (c) => c.charCodeAt(0));

  // Import the private key
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(privateKeyJwk),
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['decrypt']
  );

  // Decrypt the data
  const decrypted = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    encrypted
  );

  return decoder.decode(decrypted);
}

/**
 * Storage keys for managing encryption keys in localStorage.
 */
export const STORAGE_KEYS = {
  PUBLIC_KEY: 'logto_demo_public_key',
  PRIVATE_KEY: 'logto_demo_private_key',
  DECRYPTED_SECRET: 'logto_demo_decrypted_app_secret', // App-specific secret unique to this application
} as const;

/**
 * Initialize key pair if not already present.
 * Returns the public key that should be passed to the sign-in page.
 */
export async function initializeKeyPair(): Promise<string> {
  let publicKey = localStorage.getItem(STORAGE_KEYS.PUBLIC_KEY);
  let privateKey = localStorage.getItem(STORAGE_KEYS.PRIVATE_KEY);

  if (!publicKey || !privateKey) {
    const keyPair = await generateKeyPair();
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
    
    localStorage.setItem(STORAGE_KEYS.PUBLIC_KEY, publicKey);
    localStorage.setItem(STORAGE_KEYS.PRIVATE_KEY, privateKey);
  }

  return publicKey;
}

// Track if we're already fetching to prevent concurrent requests
let isRetrieving = false;
let lastRetrievalError: number | null = null;
const ERROR_BACKOFF_MS = 30000; // 30 seconds

/**
 * Retrieve and decrypt the app-specific secret from the user's account.
 * Each application receives a unique secret derived from the user's base secret.
 * This should be called after successful authentication.
 * @param getAccessToken - Function to get the access token from Logto SDK
 */
export async function retrieveAndDecryptSecret(
  getAccessToken: () => Promise<string | undefined>,
  getEncryptedClientSecret?: () => string | null
): Promise<string | null> {
  // Prevent concurrent requests
  if (isRetrieving) {
    return null;
  }

  // If we had an error recently, don't retry yet
  if (lastRetrievalError && Date.now() - lastRetrievalError < ERROR_BACKOFF_MS) {
    return null;
  }

  try {
    isRetrieving = true;

    // Clear any cached secret first to ensure we get a fresh one on each login
    localStorage.removeItem(STORAGE_KEYS.DECRYPTED_SECRET);

    const privateKey = localStorage.getItem(STORAGE_KEYS.PRIVATE_KEY);
    const publicKey = localStorage.getItem(STORAGE_KEYS.PUBLIC_KEY);
    if (!privateKey || !publicKey) {
      lastRetrievalError = Date.now();
      return null;
    }

    // Get the encrypted client secret from the token response
    let encryptedClientSecret: string | null = null;
    
    if (getEncryptedClientSecret) {
      encryptedClientSecret = getEncryptedClientSecret();
      if (encryptedClientSecret) {
      }
    }

    if (!encryptedClientSecret) {
      lastRetrievalError = Date.now();
      return null;
    }

    // Decrypt the client secret with our private key
    const decryptedSecret = await decryptWithPrivateKey(encryptedClientSecret, privateKey);
    
    // Cache the secret
    localStorage.setItem(STORAGE_KEYS.DECRYPTED_SECRET, decryptedSecret);
    
    return decryptedSecret;
  } catch (error) {
    lastRetrievalError = Date.now();
    return null;
  } finally {
    isRetrieving = false;
  }
}

/**
 * Clear all encryption-related data from localStorage.
 * This should be called on logout.
 */
export function clearEncryptionData(): void {
  localStorage.removeItem(STORAGE_KEYS.PUBLIC_KEY);
  localStorage.removeItem(STORAGE_KEYS.PRIVATE_KEY);
  localStorage.removeItem(STORAGE_KEYS.DECRYPTED_SECRET);
}

/**
 * Encrypt text using AES-GCM with the provided secret key.
 */
export async function encryptText(text: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();

  // Create a key from the secret
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Generate a random salt
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // Derive AES key
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Generate IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the text
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(text));

  // Combine salt, iv, and encrypted data
  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);

  // Return as base64
  return btoa(String.fromCodePoint(...combined));
}

/**
 * Decrypt text using AES-GCM with the provided secret key.
 */
export async function decryptText(encryptedText: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  try {
    // Decode from base64
    const combined = Uint8Array.from(atob(encryptedText), (char) => char.codePointAt(0)!);

    // Extract salt, iv, and encrypted data
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const encrypted = combined.slice(28);

    // Create a key from the secret
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    // Derive AES key
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100_000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Decrypt the data
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);

    return decoder.decode(decrypted);
  } catch {
    throw new Error('Failed to decrypt text. Invalid encrypted data or wrong secret.');
  }
}