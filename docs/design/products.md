```mermaid
---
title: Product Structure
---
erDiagram

    Organization {
        uuid id
        string name
        string cpe_key
    }

    Product {
        uuid id
        string name
        string cpe_key
    }

    ProductVersion {
        uuid id
        string version
    }

    ProductVersionRange {
        uuid id
        string cpe_key
        uuid version_range_id
    }

    VersionRange {
        uuid id
        string low_version
        string high_version
    }

    Advisory {
        uuid id
        string title
    }

    Vulnerability {
        uuid id
        string title
    }

    Status {
        uuid id
        string name
    }

    BasePurl {
        uuid id
        string type
        string namespace
        string name
    }

    ProductStatus {
        uuid id
        uuid advisory_id
        uuid vulnerability_id
        uuid status_id
        uuid base_purl_id
        uuid product_version_range_id
    }

    Sbom {
        uuid id
    }

    Organization || -- o{ Product : produces
    Product || -- o{ ProductVersion : have
    ProductVersion || -- || Sbom : describes

    Product || -- o{ ProductVersionRange : have
    ProductVersionRange || -- || VersionRange : belongs

    BasePurl || -- || ProductVersionRange : belongs

    ProductStatus || -- || Advisory : describes
    ProductStatus || -- || Vulnerability : describes
    ProductStatus || -- || BasePurl : describes
    ProductStatus || -- || Status : describes
    ProductStatus || -- || ProductVersionRange : describe

```
