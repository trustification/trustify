# Glossary of Understanding

## Entities

### Vulnerability

A vulnerability is mostly, primarily a *name* that is used to ensure all advisories are discussing the same thing.
Generally, to this point, most vulnerabilities come from the CVE Project, with the format of `CVE-2024-1234`.

Within the database, generally a vulnerability is added as a side effect of an advisory mentioning it.

A _CVE Record_ from NIST/NVD is a low-value advisory that is generally the first discovered advisory that mentions a vulnerability.

### Advisory

An advisory is an opinion about a vulnerability.

These opinions include the context to which the opinions apply.
These opinions include evaluation of the severity and scoring of a vulnerability within that context, such as CVSS scores.

As mentioned above, a _CVE Record_ from the CVE Project is a low-value advisory that mentions the vulnerability and provide a base opinion about it.
It may include CVSS scores, within the context of the abstract origin containing the vulnerability.
This may be simply in reference to the vulnerability _as it exists in source-code form_.

Other, more-involved stakeholders (product vendors, upstream project owners) may issue *additional* advisories.
These opinions may be in reference to _concrete_ shipped products, contextualized to how the vulnerable code is _actually used_.

### Package

A package is an atomic artifact or component.
Packages may be addressed using pURLs.
A package may be described by an SBOM describing how it is created.

### Product

A product is a _named collection of packages_ for a concrete shippable thing.

Products may be addressed using CPEs or some other future identification method.
A product may be described by an SBOM describing its components, which may be other products or packages, or their SBOMs.

NOTE: Given ProdSec definitions, grouping of Products may need to occur within some sense of Product Versions, or Product Streams.

#### Product Examples

`RHEL8` may be a _product stream_.
`RHEL 8.2.03 PowerPC` may be a concrete _product_ distinct from `RHEL 8.2.03 AArch64`.





