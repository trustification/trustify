After some tests, here's an update:

```mermaid
erDiagram
  Sbom {
    int sbom_id PK "inherited"
    string id "inherited"
    string name "inherited"
    string namespace "inherited"

    uuid sha256
  }

  Package {
    int sbom_uid FK "inherited"
    string id "inherited"
    string name "inherited"
  }

  Node {
    int sbom_id
    string id
  }

  Edge {
    int sbom_id

    string left_id
    option~string~ left_namespace

    enum~relationship~ type

    string right_id
    option~string~ right_namespace
  }

  Sbom 1 to 0+ Package : contains

  BasePurl {
    uuid id
    string type
    string name
    option~string~ namespace
  }
  VersionedPurl {
    string version
  }
  QualifiedPurl {
    jsonb qualifiers
  }

  QualifiedPurl 0+ to 1 VersionedPurl: refines
  VersionedPurl 0+ to 1 BasePurl: refines

  CPE

  Package 1 optionally to 0+ QualifiedPurl: references
  Package 1 optionally to 0+ CPE: references

  Node 1 to zero or one Package: inherits
  Node 1 to zero or one Sbom: inherits

  Edge 1 to zero or one Node: left
  Edge 1 to zero or one Node: right
```

Most notable changes:

* We keep an "SBOM ID" which we assign to ensure we can use multiple versions of SBOMs using the same namespace
* Drop the "describes" tables, as those come with the "describes" relationship
* Create a common `sbom_node` table, having `sbom` and `sbom_package` inherit from those
* Have the `package_relates_to_package` reference entries in `sbom_node`

Unresolved issues:

* A relationship can point outside the current SBOM. That's indicated by the `left_namespace` and `right_namespace`:
  * It might be that both ends are external to this document. I don't think we should support this, even if the spec might.
  * How do we handle the case where the relationship points to a target for which we have multiple SBOMs?
