/**
 * Middleware to intercept token responses and add encrypted client secrets
 * for authorization_code grant types.
 */

import type { MiddlewareType, ParameterizedContext } from 'koa';
import type { Provider } from 'oidc-provider';

import type Queries from '#src/tenants/Queries.js';
import { encryptedSecretStore } from '#src/utils/encrypted-secret-store.js';

const getUserIdFromToken = (idToken: unknown): string | undefined => {
  if (typeof idToken !== 'string') {
    return undefined;
  }

  try {
    // Decode the ID token to get the sub claim (user ID)
    // ID tokens are JWT format: header.payload.signature
    const [, payload] = idToken.split('.');
    if (!payload) {
      return undefined;
    }

    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString());
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return decodedPayload.sub;
  } catch {
    return undefined;
  }
};

const shouldProcessResponse = (ctx: ParameterizedContext): boolean => {
  // Only process token endpoint responses
  if (!ctx.path.endsWith('/token') || ctx.method !== 'POST') {
    return false;
  }

  // Check if this is an authorization_code grant
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const grantType = ctx.request.body?.grant_type || ctx.oidc?.params?.grant_type;
  if (grantType !== 'authorization_code') {
    return false;
  }

  // Only process successful responses with an ID token
  return ctx.status === 200 && Boolean(ctx.body) && typeof ctx.body === 'object';
};

export default function koaEncryptedSecretInterceptor(
  provider: Provider,
  queries: Queries,
  tenantId: string
): MiddlewareType {
  return async (ctx, next) => {
    await next();

    if (!shouldProcessResponse(ctx)) {
      return;
    }

    if (typeof ctx.body !== 'object' || !ctx.body) {
      return;
    }

    const { body } = ctx;

    if (!('id_token' in body)) {
      return;
    }

    const userId = getUserIdFromToken(body.id_token);

    if (!userId) {
      return;
    }

    try {
      // Retrieve the encrypted client secret from the in-memory store
      const encryptedClientSecret = encryptedSecretStore.get(userId);

      if (!encryptedClientSecret) {
        return;
      }

      // Add the encrypted client secret to the response body
      ctx.body = {
        ...ctx.body,
        encrypted_client_secret: encryptedClientSecret,
      };

      // Clean up the entry from the store after successful retrieval
      encryptedSecretStore.delete(userId);
    } catch {
      // Don't fail the token request on error
    }
  };
}
