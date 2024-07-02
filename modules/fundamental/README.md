# Fundamental

## Get all SBOMs for a package


By PURL:

```bash
http localhost:8080/api/v1/sbom/by-purl purl==pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1
```

By package ID (as returned by other APIs):

```bash
http localhost:8080/api/v1/sbom/by-purl id==6cfff15d-ee06-4cb7-be37-a835aed2af82
```
