# Map users to Matrix

## Testing locally

This can be tested locally to some degree. For this to work you need to create a local file called `payload.json` with
the JSON encoded data of `github.event` from an event of:

```yaml
on:
  pull_request_target:
    branches:
      - main
    types:
      - review_requested
```

Then you can run:

```shell
npm ci
```

Followed by:

```shell
npm run test
```
