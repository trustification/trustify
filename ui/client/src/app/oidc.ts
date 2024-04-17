import { OidcClientSettings } from "oidc-client-ts";
import { ENV } from "./env";

export const oidcClientSettings: OidcClientSettings = {
  authority: ENV.OIDC_SERVER_URL || "http://localhost:8090/realms/chicken",
  client_id: ENV.OIDC_CLIENT_ID || "frontend",
  redirect_uri: window.location.href,
  post_logout_redirect_uri: window.location.href.split("?")[0],
  response_type: "code",
  loadUserInfo: true,
  scope: ENV.OIDC_SCOPE || "openid",
};
