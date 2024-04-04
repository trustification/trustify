Create a new CSAF importer:

```bash
http POST localhost:8080/api/v1/importer/redhat-csaf csaf[source]=https://redhat.com/.well-known/csaf/provider-metadata.json csaf[disabled]:=false csaf[onlyPatterns][]="^cve-2023-" csaf[period]=30s csaf[v3Signatures]:=true
```

Create a new SBOM importer:

```bash
http POST localhost:8080/api/v1/importer/redhat-sbom sbom[source]=https://access.redhat.com/security/data/sbom/beta/ sbom[keys][]=https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4 sbom[disabled]:=false sbom[onlyPatterns][]=quarkus sbom[period]=30s sbom[v3Signatures]:=true
```

Get all importers:

```bash
http GET localhost:8080/api/v1/importer
```

Get a specific importer:

```bash
http GET localhost:8080/api/v1/importer/redhat-csaf
http GET localhost:8080/api/v1/importer/redhat-sbom
```

Get reports:

```bash
http GET localhost:8080/api/v1/importer/redhat-csaf/report
http GET localhost:8080/api/v1/importer/redhat-sbom/report
```

Delete an importer:

```bash
http DELETE localhost:8080/api/v1/importer/redhat-csaf
http DELETE localhost:8080/api/v1/importer/redhat-sbom
```
