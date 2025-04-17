# Building the Documentation

To build the documentation, simply run:

```console
$ make
```

For the first time, you maybe need also to execute `npm ci`:

```console
$ npm ci
$ make
```

## Building the Documentation with Tests

This repository comes with Antora extension that allows you to write tests
inside `*.adoc` files. This becomes useful when you need to be sure that your
code snippets are correct.

Currently, only JavaScript code snippets are supported, following further these
restrictions:

- `console` and `JSON` objects are accessible

- `assert`, `crypto`, `fs`, and `path` Node.js libraries are preloaded and
  accessible

- `bombastic` object as an `axios` wrapper around TPA v1 Bombastic API is
  accessible

- `trustify` object as an `axios` wrapper around TPA v2 API is accessible

To mark your code snippet as a test, just use `%test` option:

```adoc
[%test]
----
assert(true);
----
```

Key-value parameters are also supported. For now, you can set `timeout` for a
particular test and you can also give a test a `name`:

```adoc
[%test, name = "Always Pass", timeout = 1000]
----
assert(true);
----
```

### How to Run Documentation Tests

Running documentation tests is driven and customized using environment
variables:

- `ISSUER_URL` is the OIDC provider URL (default `http://localhost:8090/realms/chicken`)

- `TRUST_ID` is the ID of a user with TPA management rights (default `testing-manager`)

- `TRUST_SECRET` is the secret associated with `TRUST_ID` (default `R8A6KFeyxJsMDBhjfHbpZTIF0GWt43HP`)

- `BOMBASTIC_URL` is the TPA v1 Bombastic API endpoint URL (default `http://localhost:8082`)

- `TRUSTIFY_URL` is the TPA v2 API endpoint URL (default `http://localhost:8080`)

- `TEST_MODE` is the mode of how tests will be executed:

  - `skip` means that all tests are skipped (default)

  - `info` means that all tests are executed, errors are reported, failing tests
    are tolerated

  - `strict` means that all tests are executed, errors are reported, all tests
    must pass (any failing test cause Antora to stop processing and exit with
    a non-zero exit code)

- `TEST_TIMEOUT` specify the default timeout for tests (default 30000); may be
  overridden by the `timeout` parameter per test (see above)

- `RETRY_LIMIT` is the maximum number of API call retries (default 5)

To run documentation tests:

1. First, start TPA v1 and TPA v2 (actually these two cannot run side-by-side
   due to an OIDC port conflict)

1. Run `make` or `make build` with `TEST_MODE` set to `info` or `strict`:
   ```console
   $ TEST_MODE=info make
   ```
