export async function splitPassword(password: string): Promise<{
  serverPassword: string;
  clientPassword: string;
}> {
  const encoder = new TextEncoder();

  const serverSalt = encoder.encode('logto_server_password_salt');
  const clientSalt = encoder.encode('logto_client_password_salt');

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

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

  const serverPassword = Buffer.from(serverBits).toString('base64');
  const clientPassword = Buffer.from(clientBits).toString('base64');

  return { serverPassword, clientPassword };
}
