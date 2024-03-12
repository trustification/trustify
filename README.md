[![backend](https://github.com/trustification/trustify/actions/workflows/backend.yaml/badge.svg)](https://github.com/trustification/trustify/actions/workflows/backend.yaml)

## Repository Organization.

### Sources

#### `common`
Model-like bits shared between multiple contexts.

#### `entity`
Database entity models, implemented via SeaORM.

#### `graph`
The primary graph engine and API.

#### `importer`
Importers capable of adding documents into the graph.

#### `ingestors`
Ingestors/readers for various formats (SPDX, CSAF, CVE, OSV, etc, etc)

#### `migration`
SeaORM migrations for the DDL.

#### `server`
The REST API server.

#### `trustd`
The server CLI tool `trustd`

### Et Merde
#### `etc/deploy`
Deployment-related (such as `compose`) files.

#### `etc/test-data`
Arbitrary test-data.


## Development Environment.

**Note**
Running an external PostgreSQL is no longer recommended for unit tests.
You may wish to run one externally still for any other non-test-related activities.

Starting:

```shell
podman-compose -f etc/deploy/compose/compose.yaml up
```

Connect to PSQL:

```shell
env PGPASSWORD=eggs psql -U postgres -d huevos -h localhost -p 5432
```

Import data (also see: [importer/README.md](importer/README.md) for more options):

```shell
env DB_USER=postgres DB_PASSWORD=eggs cargo run -p trustify-trustd -- importer csaf https://www.redhat.com
env DB_USER=postgres DB_PASSWORD=eggs cargo run -p trustify-trustd -- importer sbom https://access.redhat.com/security/data/sbom/beta/
```

### Authentication

By default, authentication is enabled. It can be disabled using the flag `--auth-disabled` when running the server.
Also by default, there is no working authentication/authorization configuration. For development purposes, one can
use `--devmode` to use the Keycloak instance deployed with the compose deployment.

HTTP requests must provide the bearer token using the `Authorization` header. For that, a valid access token is
required. There are tutorials using `curl` on getting such a token. It is also possible the use the `oidc` client tool:

Installation:

```bash
cargo install oidc-cli
```

Then, set up an initial client (needs to be done every time the client/keycloak instance if re-created):

```bash
oidc create confidential --name trusty --issuer http://localhost:8090/realms/chicken --client-id walker --client-secret ZVzq9AMOVUdMY1lSohpx1jI3aW56QDPS
```

Then one can perform `http` request using HTTPie like this:

```bash
http localhost:8080/package/asdf/dependencies Authorization:$(oidc token trusty -b)
```

## Notes on models

### Package

A package exists or it does not. Represented by a pURL. No source-tracking required.

Rework to Package. VersionedPackage. QualifiedVersionedPackage. and VersionRangePackage for vulnerable references. 
Plus appropriate junction tables. 

### CPE
Probably need a fancy CPE table structure. sigh. 
Or two+ tables (cpe22, cpe23) and a Product table.
Platonic form of a product may have 0+ CPEs/pURLs.
Platonic form of a product may have 0+ known hashable artifacts.

### CVE

A CVE exists or it does not. Represented by an identifier. No source-tracking required.

### CWE

A CWE exists or it does not. Represented by an identifier. No source-tracking required.

### Advisory

An Advisory exists or it does not. Represented by a location/hash/identifier. 
Source tracked from an Advisory Source.

There is probably always an advisory from NVD for every CVE. 

### Advisory Source
Something like GHSA, Red Hat VEX, etc. Maybe?
Based on source URL? Regexp!
Still unsure here.

### Scanners don't exist
They should just point us towards first order advisories to ingest. 
OSV just tells us to look elsewhere. 
They are helpers not nouns. 

### Vulnerable
Package Range + Advisory + CVE.

### NonVulnerable
QualifiedPackage + Advisory + CVE.

Both impl'd for pURL and CPE. 

### SBOM
hashed document that claims things about stuff. 
All package/product relationships exist only within the context of an SBOM making the claim.

### Describes
CPE (Product?) and/or pURLs described by the SBOM
