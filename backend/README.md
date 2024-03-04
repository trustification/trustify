## dev-env

Starting:

```shell
podman-compose -f deploy/compose/compose.yaml up
```

Connect to PSQL:

```shell
env PGPASSWORD=eggs psql -U postgres -d huevos -h localhost -p 5432
```

Import data:

```shell
cargo run --bin huevos-cli importer csaf --source ../trustification/data/ds1/csaf --db-user postgres --db-password eggs

cargo run --bin huevos-cli importer sbom --source ../trustification/data/ds1/sbom --db-user postgres --db-password eggs
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
