# Importing data

The following commands require some env-var for connecting to the database. You can supply them e.g., using `env`:

```bash
env DB_USER=postgres DB_PASSWORD=eggs <command to run>
```

## Importing advisories

```bash
cargo run -p trustify-trustd -- importer csaf https://www.redhat.com --only-prefix cve-2023-
```

Or, using a locally cached version:

```bash
mkdir -p data/csaf
csaf sync https://www.redhat.com --only-prefix cve-2023- -d data/csaf -3
```

If you need to sync the content without validation, you can use the `download` command:

```bash
csaf download https://www.redhat.com --only-prefix cve-2023- -d data/csaf
```

And then:

```bash
cargo run -p trustify-trustd -- importer csaf data/csaf
```

## Importing SBOMs

```bash
cargo run -p trustify-trustd -- importer sbom https://access.redhat.com/security/data/sbom/beta/
```

Or, using a locally cached version:

```bash
mkdir -p data/sbom
sbom sync https://access.redhat.com/security/data/sbom/beta/ -d data/sbom --key https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4 -3
```

If you need to sync the content without validation, you can use the `download` command:

```bash
sbom download https://access.redhat.com/security/data/sbom/beta/ -d data/sbom --key https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4
```

And then:

```bash
cargo run -p trustify-trustd -- importer sbom data/sbom
```
