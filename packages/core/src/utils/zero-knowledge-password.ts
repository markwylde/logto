/**
 * Server-side password splitting for zero-knowledge encryption.
 * This is used when the admin resets a user's password.
 */

import crypto from 'node:crypto';
import { promisify } from 'node:util';

const pbkdf2 = promisify(crypto.pbkdf2);

/**
 * Split a password into server and client parts using PBKDF2.
 * This must match the client-side implementation exactly.
 */
export async function splitPassword(password: string): Promise<{
  serverPassword: string;
  clientPassword: string;
}> {
  // Use the same salts as the client
  const serverSalt = Buffer.from('logto_server_password_salt', 'utf8');
  const clientSalt = Buffer.from('logto_client_password_salt', 'utf8');

  // Derive server password
  const serverBits = await pbkdf2(password, serverSalt, 100_000, 32, 'sha256');
  const serverPassword = serverBits.toString('base64');

  // Derive client password
  const clientBits = await pbkdf2(password, clientSalt, 100_000, 32, 'sha256');
  const clientPassword = clientBits.toString('base64');

  return { serverPassword, clientPassword };
}
