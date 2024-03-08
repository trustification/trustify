# Importing data

The following commands require some env-var for connecting to the database. You can supply them e.g., using `env`:

```bash
env DB_USER=postgres DB_PASSWORD=eggs <command to run>
```

## Importing advisories

```bash
cargo run -p trustify-cli -- importer csaf https://www.redhat.com --only-prefix cve-2023-
```

Or, using a locally cached version:

```bash
mkdir data/csaf
csaf download https://www.redhat.com --only-prefix cve-2023- -d data/csaf
```

And then:

```bash
cargo run -p trustify-cli -- importer csaf data/csaf
```

## Importing SBOMs
