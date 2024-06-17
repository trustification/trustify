# trustify

[![ci](https://github.com/trustification/trustify/actions/workflows/ci.yaml/badge.svg)](https://github.com/trustification/trustify/actions/workflows/ci.yaml)

## Quick start

Let's call this "PM mode":

```shell
cargo run --bin trustd
```

That will create its own database on your local filesystem.

* To use the **UI**, navigate to: <http://localhost:8080>.
* To use the **Swagger UI**, navigate to: <http://localhost:8080/openapi/>.

### Running containerized UI

You can also fire up the UI using:

```shell
podman run --network="host" --pull=always \
-e TRUSTIFY_API_URL=http://localhost:8080 \
-e OIDC_CLIENT_ID=frontend \
-e OIDC_SERVER_URL=http://localhost:8090/realms/trustify \
-e ANALYTICS_ENABLED=false \
-e PORT=3000 \
-p 3000:3000 \
ghcr.io/trustification/trustify-ui:latest
```

Open the UI at <http://localhost:3000>

## Repository Organization

### Sources

#### `common`

Model-like bits shared between multiple contexts.

#### `entity`

Database entity models, implemented via SeaORM.

#### `migration`

SeaORM migrations for the DDL.

#### `modules/graph`

The primary graph engine and API.

#### `modules/importer`

Importers capable of adding documents into the graph.

#### `modules/ingestor`

Ingestors/readers for various formats (SPDX, CSAF, CVE, OSV, etc, etc)

#### `server`

The REST API server.

#### `trustd`

The server CLI tool `trustd`

### Et Merde

#### `etc/deploy`

Deployment-related (such as `compose`) files.

#### `etc/test-data`

Arbitrary test-data.

## Development Environment

### Postgres

Unit tests and "PM mode" use an embedded instance of Postgres that is
installed as required on the local filesystem. This is convenient for
local development but you can also configure the app to use an
external database.

Starting a containerized Postgres instance:

```shell
podman-compose -f etc/deploy/compose/compose.yaml up
```

Connect to PSQL:

```shell
env PGPASSWORD=eggs psql -U postgres -d trustify -h localhost -p 5432
```

Point the app at an external db:

```shell
trustd api --help
RUST_LOG=info trustd api --db-password eggs --devmode --auth-disabled
```

#### If test failures on OSX

Potentially our concurrent Postgres installations during testing can exhaust shared-memory.
Adjusting shared-memory on OSX is not straight-forward.
Use [this guide](https://unix.stackexchange.com/questions/689295/values-from-sysctl-a-dont-match-etc-sysctl-conf-even-after-restart).

### Import some data

Import data (also see: [modules/importer/README.md](modules/importer/README.md) for more options):

```shell
# SBOM's
http POST localhost:8080/api/v1/importer/redhat-sbom sbom[source]=https://access.redhat.com/security/data/sbom/beta/ sbom[keys][]=https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4 sbom[disabled]:=false sbom[onlyPatterns][]=quarkus sbom[period]=30s sbom[v3Signatures]:=true
# CSAF's
http POST localhost:8080/api/v1/importer/redhat-csaf csaf[source]=https://redhat.com/.well-known/csaf/provider-metadata.json csaf[disabled]:=false csaf[onlyPatterns][]="^cve-2023-" csaf[period]=30s csaf[v3Signatures]:=true
```

### Authentication

By default, authentication is enabled. It can be disabled using the flag `--auth-disabled` when running the server.
Also. by default, there is no working authentication/authorization configuration. For development purposes, one can
use `--devmode` to use the Keycloak instance deployed with the compose deployment.

Also see: [docs/oidc.md](docs/oidc.md)

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
