import React, { Suspense } from "react";
import { AuthProvider, useAuth } from "react-oidc-context";
import { oidcClientSettings } from "@app/oidc";
import ENV from "@app/env";
import { AppPlaceholder } from "./AppPlaceholder";
import { initInterceptors } from "@app/axios-config";

interface IOidcProviderProps {
  children: React.ReactNode;
}

export const OidcProvider: React.FC<IOidcProviderProps> = ({ children }) => {
  return ENV.AUTH_REQUIRED !== "true" ? (
    <>{children}</>
  ) : (
    <AuthProvider
      {...oidcClientSettings}
      automaticSilentRenew={true}
      onSigninCallback={() =>
        window.history.replaceState(
          {},
          document.title,
          window.location.pathname
        )
      }
    >
      <AuthEnabledOidcProvider>{children}</AuthEnabledOidcProvider>
    </AuthProvider>
  );
};

const AuthEnabledOidcProvider: React.FC<IOidcProviderProps> = ({
  children,
}) => {
  const auth = useAuth();

  React.useEffect(() => {
    if (!auth.isAuthenticated && !auth.isLoading) {
      auth.signinRedirect();
    }
  }, [auth.isAuthenticated, auth.isLoading]);

  React.useEffect(() => {
    initInterceptors();
  }, []);

  if (auth.isAuthenticated) {
    return <Suspense fallback={<AppPlaceholder />}>{children}</Suspense>;
  } else if (auth.isLoading) {
    return <AppPlaceholder />;
  } else {
    return <p>Login in...</p>;
  }
};
