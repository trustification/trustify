Create a new SBOM importer:

```bash
http POST localhost:8080/api/v1/importer/test sbom[source]=https://access.redhat.com/security/data/sbom/beta/ sbom[keys][]=https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4 sbom[disabled]:=false sbom[onlyPatterns][]=quarkus sbom[period]=30s
```

Get all importer:

```bash
http GET localhost:8080/api/v1/importer
```

Get a specific importer:

```bash
http GET localhost:8080/api/v1/importer/test
```

Get reports:

```bash
http GET localhost:8080/api/v1/importer/test/report
```
