## dev-env

Starting:

```shell
podman-compose -f deploy/compose/compose.yaml up
```

Connect to PSQL:

```shell
env PGPASSWORD=eggs psql -U postgres -d huevos -h localhost -p 5432
```

## Notes on models

### Package

A package exists or it does not. Represented by a pURL. No source-tracking required.

### CVE

A CVE exists or it does not. Represented by an identifier. No source-tracking required.

### CWE

A CWE exists or it does not. Represented by an identifier. No source-tracking required.

### Advisory

An Advisory exists or it does not. Represented by a location/hash/identifier. 
Source tracked from an Advisory Source.

### Advisory Source
Something like GHSA, Red Hat VEX, etc.

### Vulnerability
Not yet implemented, but represents a mixture of CVE+(package + range)+Advisory

### NonVulnerability
Not yet implemented, but represents a mixture of CVE+(package + range)+Advisory


