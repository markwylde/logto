import { GoogleConnector, logtoGoogleOneTapCookieKey } from '@logto/connector-kit';
import { useLogto } from '@logto/react';
import { ExtraParamsKey } from '@logto/schemas';
import { conditional } from '@silverhand/essentials';
import { useContext, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getCookie } from 'tiny-cookie';

import AppLoading from '@/components/AppLoading';
import { TenantsContext } from '@/contexts/TenantsProvider';
import useRedirectUri from '@/hooks/use-redirect-uri';

enum ExternalGoogleOneTapLandingSearchParams {
  Credential = 'credential',
}
/** The external Google One Tap landing page for external website integration. */
function ExternalGoogleOneTapLanding() {
  const navigate = useNavigate();
  const { isAuthenticated, signIn } = useLogto();
  const { navigateTenant } = useContext(TenantsContext);
  const redirectUri = useRedirectUri();
  const [searchParams] = useSearchParams();
  const credentialParam = searchParams.get(ExternalGoogleOneTapLandingSearchParams.Credential);
  const cookieCredential = getCookie(logtoGoogleOneTapCookieKey) ?? undefined;
  const credential = credentialParam ?? cookieCredential;

  useEffect(() => {
    if (isAuthenticated || !credential) {
      // Navigate to root, which will handle tenant selection
      navigate('/', { replace: true });
      return;
    }

    // Use OIDC extraParams to transport the credential to Experience package
    void signIn({
      redirectUri,
      /**
       * Cannot clear tokens here since the user may already have tokens and let the user select which account to keep.
       * We can hence clear tokens in the <Callback /> page.
       */
      clearTokens: false,
      directSignIn: {
        method: 'social',
        target: GoogleConnector.target,
      },
      ...conditional(
        credential && {
          extraParams: {
            [ExtraParamsKey.GoogleOneTapCredential]: credential,
          },
        }
      ),
    });
  }, [isAuthenticated, navigate, navigateTenant, signIn, redirectUri, credential]);

  return <AppLoading />;
}

export default ExternalGoogleOneTapLanding;
