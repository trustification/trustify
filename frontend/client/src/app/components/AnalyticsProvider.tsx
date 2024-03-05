import React, { useEffect } from "react";
import { useLocation } from "react-router";
import { useAuth } from "react-oidc-context";
import { AnalyticsBrowser } from "@segment/analytics-next";
import ENV from "@app/env";
import { isAuthRequired } from "@app/Constants";
import { analyticsSettings } from "@app/analytics";

const AnalyticsContext = React.createContext<AnalyticsBrowser>(undefined!);

interface IAnalyticsProviderProps {
  children: React.ReactNode;
}

export const AnalyticsProvider: React.FC<IAnalyticsProviderProps> = ({
  children,
}) => {
  return ENV.ANALYTICS_ENABLED !== "true" ? (
    <>{children}</>
  ) : (
    <AnalyticsContextProvider>{children}</AnalyticsContextProvider>
  );
};

export const AnalyticsContextProvider: React.FC<IAnalyticsProviderProps> = ({
  children,
}) => {
  const auth = (isAuthRequired && useAuth()) || undefined;
  const analytics = React.useMemo(() => {
    return AnalyticsBrowser.load(analyticsSettings);
  }, []);

  // Identify
  useEffect(() => {
    if (auth) {
      const claims = auth.user?.profile;
      analytics.identify(claims?.sub, {
        organization_id: (claims?.organization as any)?.id,
        domain: claims?.email?.split("@")[1],
      });
    }
  }, [auth, analytics]);

  // Watch navigation
  const location = useLocation();
  useEffect(() => {
    analytics.page();
  }, [location]);

  return (
    <AnalyticsContext.Provider value={analytics}>
      {children}
    </AnalyticsContext.Provider>
  );
};
