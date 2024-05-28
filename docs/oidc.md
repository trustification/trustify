# OIDC

By default, Trustify requires an OIDC server. You will need to understand OIDC and set up a secure instance.

There are a few options to make your life easier. However, they all have some implications.

## Keycloak

You can start the pre-configured Keycloak instance using podman compose:

```bash
podman compose -f etc/deploy/compose/compose.yaml -f etc/deploy/compose/compose-sso.yaml up
```

> [!WARNING]
> This setup contains well-known credentials, which are not secure!

## Embedded OIDC server

You can enable an embedded OIDC server instead of using an external one.

> [!CAUTION]
> The embedded OIDC server is just a mock server. This may be ok for demo purposes, but it is a serious security issue
> in most other cases.

It needs to be enabled during compilation using `--features pm` and can then be enabled using the `--embedded-oidc`
flag. Enabling the feature will automatically enable it when running in "PM mode".

## Disable authentication

You can start `trustd` with `--disable-auth` option disable authentication altogether.

> [!CAUTION]
> Disabling authentication may be ok for demo purposes, but it is a serious security issue in most other cases.



