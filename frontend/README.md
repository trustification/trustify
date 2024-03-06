# frontend

## dev-env

### Install node and npm

Use [nvm](https://github.com/nvm-sh/nvm?tab=readme-ov-file#install--update-script)
that installs both node and npm.

Then

```shell
nvm install node
node --version
npm --version
```

### Install dependencies:

```shell
npm clean-install --ignore-scripts
```

### Init the dev server:

```shell
npm run start:dev
```

Open browser at <http://localhost:3000>

## Environment variables

| ENV VAR                | Description                   | Defaul value                         |
| ---------------------- | ----------------------------- | ------------------------------------ |
| TRUSTIFICATION_HUB_URL | Set Trustification API URL    | http://localhost:8080                |
| AUTH_REQUIRED          | Enable/Disable authentication | false                                |
| OIDC_CLIENT_ID         | Set Oidc Client               | frontend                             |
| OIDC_SERVER_URL        | Set Oidc Server URL           | http://localhost:8090/realms/chicken |
| OIDC_Scope             | Set Oidc Scope                | openid                               |
| ANALYTICS_ENABLED      | Enable/Disable analytics      | false                                |
| ANALYTICS_WRITE_KEY    | Set Segment Write key         | null                                 |
