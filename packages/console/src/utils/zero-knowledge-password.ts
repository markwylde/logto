/**
 * Client-side password splitting for zero-knowledge encryption in admin console.
 * This ensures admin operations use the same password splitting as the main app.
 */

/**
 * Split a password into server and client parts using PBKDF2.
 * This must match the implementation in other client packages.
 */
export async function splitPassword(password: string): Promise<{
  serverPassword: string;
  clientPassword: string;
}> {
  const encoder = new TextEncoder();

  // Use the same salts as other client implementations
  const serverSalt = encoder.encode('logto_server_password_salt');
  const clientSalt = encoder.encode('logto_client_password_salt');

  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  // Derive server password
  const serverBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: serverSalt,
      iterations: 100_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  // Derive client password
  const clientBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: clientSalt,
      iterations: 100_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  // Convert to base64
  const serverPassword = Buffer.from(serverBits).toString('base64');
  const clientPassword = Buffer.from(clientBits).toString('base64');

  return { serverPassword, clientPassword };
}
