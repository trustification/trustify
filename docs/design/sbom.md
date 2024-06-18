Database layout for storing SBOM information.

When storing an SBOM, we extract parts of it into the database, and also store the full document should we need it in
the future.

We do extract the following components out of the SBOM:

* Basic document metadata
* Packages
* Relationships between packages

We also detect PURLs and CPEs, and create database entries for those as well if they don't exist yet.

An SBOM contains a list of packages, which are connected by relationships (like A depends on B). For some SBOM formats
(e.g. SPDX), this may include references to the document itself (A describes SBOM), or to external documents
(SBOM-A amends SBOM-B) and packages in external documents (A depends on SBOM-B/C).

To represent this graph of SBOM, packages and relationships, the model of SPDX is being used, as it also covers the
features of CycloneDX. In the database, this is being represented by the following structure:

```mermaid
erDiagram
    Sbom {
        uuid sbom_id PK, FK "unique ID of the SBOM"
        string node_id "ID of the SBOM document element in the scope of this SBOM"

        string document_id "ID from the content of the document"
        string sha256 "SHA256 digest of the document content"
    }

    Package {
        uuid sbom_id PK, FK "unique ID of the SBOM this package belongs"
        string node_id PK, FK "ID of the SBOM package element in the scope of this SBOM"
    }

    Node {
        uuid sbom_id PK "unique ID of the SBOM this node belongs to"
        string node_id PK "ID of the SBOM element in the scope of this SBOM"
        
        string name "The name of the node"
    }

    Relationship {
        int sbom_id
        string left_node_id
        enum~relationship~ type
        string right_node_id
    }

    Sbom 1 to 0+ Package: contains

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
    Relationship 1 to zero or one Node: left
    Relationship 1 to zero or one Node: right
```

The `Node` table contains all possible targets for references. This can be either an SBOM or a package of an SBOM.
Creating a matching entry in the `SBOM` table, makes this node of the graph an SBOM. Adding an entry in the `Package`
table makes it a package. The relationship table links the nodes together.

The SBOM ID is an artificially generated unique ID. The node IDs are taken from the content of the SBOM and are only
considered unique in the scope of the SBOM.

The trio of `QualifiedPurl`, `VersionedPurl`, and `BasePurl` describe what used to be known as "package", but which did
not fully reflect the SBOMs model, as SBOM packages are an entity of their own, but may have zero or more PURLs or
CPEs (or other identifiers).
