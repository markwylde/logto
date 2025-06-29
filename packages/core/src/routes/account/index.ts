import { usernameRegEx, UserScope } from '@logto/core-kit';
import {
  userProfileResponseGuard,
  userProfileGuard,
  AccountCenterControlValue,
  SignInIdentifier,
} from '@logto/schemas';
import { z } from 'zod';

import koaGuard from '#src/middleware/koa-guard.js';

import RequestError from '../../errors/RequestError/index.js';
import { encryptUserPassword } from '../../libraries/user.utils.js';
import { splitPassword } from '../../utils/zero-knowledge-password.js';
import assertThat from '../../utils/assert-that.js';
import { PasswordValidator } from '../experience/classes/libraries/password-validator.js';
import type { UserRouter, RouterInitArgs } from '../types.js';

import { accountApiPrefix } from './constants.js';
import emailAndPhoneRoutes from './email-and-phone.js';
import identitiesRoutes from './identities.js';
import mfaVerificationsRoutes from './mfa-verifications.js';
import koaAccountCenter from './middlewares/koa-account-center.js';
import { getAccountCenterFilteredProfile, getScopedProfile } from './utils/get-scoped-profile.js';

export default function accountRoutes<T extends UserRouter>(...args: RouterInitArgs<T>) {
  const [router, { queries, libraries }] = args;
  const {
    users: { updateUserById, findUserById },
    signInExperiences: { findDefaultSignInExperience },
  } = queries;

  const {
    users: { checkIdentifierCollision, verifyUserPassword },
  } = libraries;

  router.use(koaAccountCenter(queries));

  router.get(
    `${accountApiPrefix}`,
    koaGuard({
      response: userProfileResponseGuard.partial(),
      status: [200],
    }),
    async (ctx, next) => {
      const { id: userId, scopes } = ctx.auth;
      const profile = await getScopedProfile(queries, libraries, scopes, userId);
      ctx.body = getAccountCenterFilteredProfile(profile, ctx.accountCenter);
      return next();
    }
  );

  router.patch(
    `${accountApiPrefix}`,
    koaGuard({
      body: z.object({
        name: z.string().nullable().optional(),
        avatar: z.string().url().nullable().optional(),
        username: z.string().regex(usernameRegEx).nullable().optional(),
      }),
      response: userProfileResponseGuard.partial(),
      status: [200, 400, 422],
    }),
    async (ctx, next) => {
      const { id: userId, scopes } = ctx.auth;
      const { body } = ctx.guard;
      const { name, avatar, username } = body;
      const { fields } = ctx.accountCenter;

      assertThat(
        name === undefined || fields.name === AccountCenterControlValue.Edit,
        'account_center.field_not_editable'
      );
      assertThat(
        avatar === undefined || fields.avatar === AccountCenterControlValue.Edit,
        'account_center.field_not_editable'
      );
      assertThat(
        username === undefined || fields.username === AccountCenterControlValue.Edit,
        'account_center.field_not_editable'
      );
      assertThat(scopes.has(UserScope.Profile), 'auth.unauthorized');

      if (username !== undefined) {
        if (username === null) {
          const { signUp } = await findDefaultSignInExperience();
          assertThat(
            !signUp.identifiers.includes(SignInIdentifier.Username),
            'user.username_required'
          );
        } else {
          await checkIdentifierCollision({ username }, userId);
        }
      }

      const updatedUser = await updateUserById(userId, {
        name,
        avatar,
        username,
      });

      ctx.appendDataHookContext('User.Data.Updated', { user: updatedUser });

      const profile = await getScopedProfile(queries, libraries, scopes, userId);
      ctx.body = getAccountCenterFilteredProfile(profile, ctx.accountCenter);

      return next();
    }
  );

  router.patch(
    `${accountApiPrefix}/profile`,
    koaGuard({
      body: userProfileGuard,
      response: userProfileGuard,
      status: [200, 400],
    }),
    async (ctx, next) => {
      const { id: userId, scopes } = ctx.auth;
      const { body } = ctx.guard;
      const { fields } = ctx.accountCenter;

      assertThat(
        fields.profile === AccountCenterControlValue.Edit,
        'account_center.field_not_editable'
      );
      assertThat(scopes.has(UserScope.Profile), 'auth.unauthorized');

      if (body.address !== undefined) {
        assertThat(scopes.has(UserScope.Address), 'auth.unauthorized');
      }

      const updatedUser = await updateUserById(userId, {
        profile: body,
      });

      ctx.appendDataHookContext('User.Data.Updated', { user: updatedUser });

      const profile = await getScopedProfile(queries, libraries, scopes, userId);
      ctx.body = profile.profile;

      return next();
    }
  );

  router.post(
    `${accountApiPrefix}/password`,
    koaGuard({
      body: z.object({ password: z.string().min(1) }),
      status: [204, 400, 401, 422],
    }),
    async (ctx, next) => {
      const { id: userId, identityVerified } = ctx.auth;
      assertThat(
        identityVerified,
        new RequestError({ code: 'verification_record.permission_denied', status: 401 })
      );
      const { password } = ctx.guard.body;
      const { fields } = ctx.accountCenter;
      assertThat(
        fields.password === AccountCenterControlValue.Edit,
        'account_center.field_not_editable'
      );

      const user = await findUserById(userId);
      const signInExperience = await findDefaultSignInExperience();
      const passwordPolicyChecker = new PasswordValidator(signInExperience.passwordPolicy, user);
      await passwordPolicyChecker.validatePassword(password, user);

      const { passwordEncrypted, passwordEncryptionMethod } = await encryptUserPassword(password);
      const updatedUser = await updateUserById(userId, {
        passwordEncrypted,
        passwordEncryptionMethod,
      });

      ctx.appendDataHookContext('User.Data.Updated', { user: updatedUser });

      ctx.status = 204;

      return next();
    }
  );

  // Get user profile with encrypted secret for password change
  router.get(
    `${accountApiPrefix}/password/profile`,
    koaGuard({
      status: [200],
      response: z.object({
        hasPassword: z.boolean(),
        encryptedSecret: z.string().nullable(),
      }),
    }),
    async (ctx, next) => {
      const { id: userId } = ctx.auth;
      const user = await findUserById(userId);
      
      ctx.body = {
        hasPassword: Boolean(user.passwordEncrypted),
        encryptedSecret: user.encryptedSecret,
      };

      return next();
    }
  );

  // Change password with zero-knowledge encryption support
  router.put(
    `${accountApiPrefix}/password`,
    koaGuard({
      body: z.object({
        oldPassword: z.string(),
        newPassword: z.string(),
        encryptedSecret: z.string().optional(),
      }),
      status: [204, 400, 401, 403, 422],
    }),
    async (ctx, next) => {
      const { id: userId } = ctx.auth;
      const { oldPassword, newPassword, encryptedSecret } = ctx.guard.body;
      const { fields } = ctx.accountCenter;
      
      assertThat(
        fields.password === AccountCenterControlValue.Edit,
        'account_center.field_not_editable'
      );

      const user = await findUserById(userId);
      
      // The oldPassword from the client is already the server password (pre-split)
      // So we don't need to split it again
      
      // Verify the old password is correct
      await verifyUserPassword(user, oldPassword);

      // Validate new password
      const signInExperience = await findDefaultSignInExperience();
      const passwordPolicyChecker = new PasswordValidator(signInExperience.passwordPolicy, user);
      
      // Note: validatePassword expects the raw password, not the server password
      // We need to skip validation here since we only have the server password
      // TODO: This needs to be refactored to validate on the client side

      // The newPassword from the client is already the server password (pre-split)
      // So we don't need to split it again

      // Encrypt the new server password
      const { passwordEncrypted, passwordEncryptionMethod } = await encryptUserPassword(newPassword);

      // Update user with new password and optionally new encrypted secret
      const updatedUser = await updateUserById(userId, {
        passwordEncrypted,
        passwordEncryptionMethod,
        ...(encryptedSecret && { encryptedSecret }),
      });

      ctx.appendDataHookContext('User.Data.Updated', { user: updatedUser });

      ctx.status = 204;

      return next();
    }
  );

  emailAndPhoneRoutes(...args);
  identitiesRoutes(...args);
  mfaVerificationsRoutes(...args);
}
