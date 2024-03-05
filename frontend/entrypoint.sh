#!/bin/bash

set -e

if [[ -z "$TRUSTIFICATION_HUB_URL" ]]; then
  echo "You must provide TRUSTIFICATION_HUB_URL environment variable" 1>&2
  exit 1
fi

if [[ $AUTH_REQUIRED != "false" ]]; then
  if [[ -z "$OIDC_CLIENT_ID" ]]; then
    echo "You must provide OIDC_CLIENT_ID environment variable" 1>&2
    exit 1
  fi
  if [[ -z "$OIDC_SERVER_URL" ]]; then
    echo "You must provide OIDC_SERVER_URL environment variable" 1>&2
    exit 1
  fi
fi

if [[ $ANALYTICS_ENABLED != "false" ]]; then
  if [[ -z "$ANALYTICS_WRITE_KEY" ]]; then
    echo "You must provide ANALYTICS_WRITE_KEY environment variable" 1>&2
    exit 1
  fi
fi

exec node --enable-source-maps server/dist/index.js
