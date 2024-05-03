Find SBOMs:

```bash
http GET localhost:8080/api/v1/sbom limit==5 offset==0
```

Retrieve SBOM:

```bash
http GET localhost:8080/sboms/1
```

Get SBOM packages:

```bash
http GET localhost:8080/api/v1/sbom/1/packages limit==5 offset==0
```

Get SBOM top-level packages:

```bash
http GET localhost:8080/api/v1/sbom/1/packages limit==5 offset==0 root==true
```

Get related packages:

```bash
http GET localhost:8080/api/v1/sbom/1/related limit==5 offset==0 reference==<purl>
```

You can add `which==<left|right>` to declare which side of the reference you want to search for.

It also is possible to limit the search to a specific relationship type by providing `relationship==<relationship>`.

For example:

```bash
http GET localhost:8080/api/v1/sbom/1/related limit==5 offset==0 reference==pkg://maven/com.redhat.quarkus.platform/quarkus-bom@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=pom which==right
```
