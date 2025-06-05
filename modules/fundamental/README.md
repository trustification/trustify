# Fundamental

## Get all SBOMs for a package

By PURL:

```bash
http localhost:8080/api/v2/sbom/by-purl purl==pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1
```

By package ID (as returned by other APIs):

```bash
http localhost:8080/api/v2/sbom/by-purl id==6cfff15d-ee06-4cb7-be37-a835aed2af82
```

## Labels

**NOTE:** The allowing examples use SBOMs. It works the same way with advisories.

All examples in this section expect the environment variable `ID`
to point to an SBOM/advisory in the form of `urn:uuid:<id>`.

## Get labels

```bash
http localhost:8080/api/v2/sbom/$ID | jq .labels
```

## Mutate labels

Replace all labels:

```bash
http PUT localhost:8080/api/v2/sbom/$ID/label foo=bar bar=baz baz= 
```

This will replace all existing labels with the following labels:

| Key   | Value   |
|-------|---------|
| `foo` | `bar`   |
| `bar` | `baz`   |
| `baz` | *empty* |

Update (patch) labels:

```bash
http PATCH localhost:8080/api/v2/sbom/$ID/label foo=bar bar=
```

This will set `foo` to `bar` and remove the label `bar`.

## Search by labels

```bash
http GET localhost:8080/api/v2/sbom 'q==label:foo=bar' | jq '.items[] | {id, name, labels}'
```

## Signatures

**NOTE:** The allowing examples use SBOMs. It works the same way with advisories.

All examples in this section expect the environment variable `ID`
to point to an SBOM/advisory in the form of `urn:uuid:<id>`.

### Get all signatures of an SBOM

```bash
http GET localhost:8080/api/v2/sbom/$ID/signature
```

### Verify all signatures against all trust anchors

```bash
http GET localhost:8080/api/v2/sbom/$ID/verify
```
