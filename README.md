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

Rework to Package. VersionedPackage. QualifiedVersionedPackage. and VersionRangePackage for vulnerable references. 
Plus appropriate junction tables. 

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

### Scanners don't exist
They should just point us towards first order advisories to ingest. 
OSV just tells us to look elsewhere. 
They are hlpers not nouns. 

### Vulnerable
Not yet implemented, but represents a mixture of CVE+(package + range)+Advisory

### NonVulnerable
Not yet implemented, but represents a mixture of CVE+(package + range)+Advisory

Both impl'd for pURL and CPE. 

### SBOM
hashed document that claims things about stuff. 

### Describes
CPE and/or pURLs described by the SBOM

### Dependency 
Things it contains. 

### PackageDependency
Within the context of an SBOM the dependencies it claims exist between packages. 
No package dependenxy exists without an SBOM claimant. 


