# 00009. create new field in license.

Date: 2025-07-27

## Status

DRAFT

## Context
In the new license search requirements, there is a section called license summary, which requires collecting usage statistics for all licenses that appear, including how many packages and SBOMs use each license. 

## The current status of licenses in Trustify.
Currently, Trustify’s support for licenses is as follows：
In SPDX, there are two types of licenses: licenseDeclared and licenseConcluded, and the representation is mainly in the form of license expressions, which can include custom license references (licenseRef).

CycloneDX uses only one type, licenseDeclared, but offers three ways to represent it:

- ID: This is a standard SPDX license ID.
- License expression: Similar to SPDX, it supports license expressions.
- Name: This is similar to a custom license reference, allowing for user-defined license names
  In Trustify, the handling is as follows:

When processing SPDX, Trustify parses the license expression into standard SPDX license IDs and exceptions, and stores them in spdx_licenses and spdx_license_exceptions. All custom license references (LicenseRef) are filtered out[3], while the original expression is preserved in the text field.

When processing CycloneDX, there are three scenarios:

- If the license is an ID, the value is saved directly in the text field and spdx_licenses.
- If the license is a name: The value is saved directly in the text field, and both spdx_licenses and spdx_license_exceptions remain empty.
- If the license is an expression: Trustify parses it into standard SPDX license IDs and exceptions, stores them in spdx_licenses and spdx_license_exceptions, and also preserves the original expression in the text field.

## The current issue
- In CycloneDX, when the license type is 'name', Trustify only stores it in a text field, and we cannot determine whether this field represents just a name.
- In SPDX, when a license expression contains a custom license ID, Trustify also saves it only in a text field, and filters out the custom license ID during the process of parsing it into standard SPDX license IDs and exceptions.
- In SPDX, when a license expression includes a custom license ID, the custom license ID itself is meaningless and only has significance within the current SBOM, so it cannot be used for statistics or searches.

## Decision
Add a new field named custom_license_refs to the license table and Its type is list., which includes licenses of type name appearing in CycloneDX, as well as license expressions that contain custom licenses in SPDX.
```sql
ALTER TABLE license ADD COLUMN custom_license_refs text[];
```

- CycloneDX
  
  Licenses of type 'name
```json
  {
  "bom-ref": "pkg:rpm/centos/audit-libs@3.0-0.17.20191104git1c2f876.el8?arch=x86_64&upstream=audit-3.0-0.17.20191104git1c2f876.el8.src.rpm&distro=centos-8&package-id=05587266ec4157c9",
  "type": "library",
  "publisher": "CentOS",
  "name": "audit-libs",
  "version": "3.0-0.17.20191104git1c2f876.el8",
  "licenses": [
    {
      "license": {
        "name": "LGPLv2+"
      }
    }
  ],
  "cpe": "cpe:2.3:a:audit-libs:audit-libs:3.0-0.17.20191104git1c2f876.el8:*:*:*:*:*:*:*",
  "purl": "pkg:rpm/centos/audit-libs@3.0-0.17.20191104git1c2f876.el8?arch=x86_64&upstream=audit-3.0-0.17.20191104git1c2f876.el8.src.rpm&distro=centos-8",
  "properties": [
    {
      "name": "syft:package:foundBy",
      "value": "rpm-db-cataloger"
    },
    ...
  ]
},
```
`custom_license_refs` should be a jsonb mapping custom all license identifiers to their descriptions or SPDX expressions.
Example:
  ```json
  {
  "LGPLv2+": "LGPLv2+"
}
```
2 SPDX
  License expression

  ```json
    {
    "SPDXID": "SPDXRef-2a02a923-8a04-489d-9cbc-80f2d23de5ea",
    "copyrightText": "NOASSERTION",
    "downloadLocation": "https://access.redhat.com/downloads/content/package-browser",
    "externalRefs": [
      {
        "referenceCategory": "PACKAGE_MANAGER",
        "referenceLocator": "pkg:rpm/redhat/foreman-bootloaders-redhat@202102220000-1.el8sat?arch=src",
        "referenceType": "purl"
      },
      ...
     
    ],
    "filesAnalyzed": false,
    "licenseConcluded": "NOASSERTION",
    "licenseDeclared": "LicenseRef-2 AND LicenseRef-11 AND LicenseRef-BSD",
    "name": "foreman-bootloaders-redhat",
    "originator": "NOASSERTION",
    "packageFileName": "foreman-bootloaders-redhat-202102220000-1.el8sat.src.rpm",
    "supplier": "Organization: Red Hat",
    "versionInfo": "202102220000-1.el8sat"
  },
  ```
  custom license
  ```json
  {
  "comment": "External License Info is obtained from a build system which predates the SPDX specification and is not strict in accepting valid SPDX licenses.",
  "extractedText": "The license info found in the package meta data is: GPLv2+. See the specific package info in this SPDX document or the package itself for more details.",
  "licenseId": "LicenseRef-2",
  "name": "GPLv2+"
  },
  {
  "comment": "External License Info is obtained from a build system which predates the SPDX specification and is not strict in accepting valid SPDX licenses.",
  "extractedText": "The license info found in the package meta data is: GPLv3+. See the specific package info in this SPDX document or the package itself for more details.",
  "licenseId": "LicenseRef-11",
  "name": "GPLv3+"
  },
  {
  "comment": "External License Info is obtained from a build system which predates the SPDX specification and is not strict in accepting valid SPDX licenses.",
  "extractedText": "The license info found in the package meta data is: BSD. See the specific package info in this SPDX document or the package itself for more details.",
  "licenseId": "LicenseRef-BSD",
  "name": "BSD"
  },
```

  custom_license_refs
  ```json
  "LicenseRef-2:GPLv2+
   LicenseRef-11:GPLv3+
   LicenseRef-BSD:BSD"
```