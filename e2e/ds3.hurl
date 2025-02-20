# Upload the dataset
POST http://localhost:8080/api/v2/dataset
file,etc/datasets/ds3.zip;

HTTP 201

[Asserts]
jsonpath "$.files.['spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2'].id" exists
jsonpath "$.files.['spdx/ubi8-8.8-1067.json.bz2'].id" exists

[Captures]
quarkus_sbom_id: jsonpath "$.files.['spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2'].id"
ubi8_sbom_id: jsonpath "$.files.['spdx/ubi8-8.8-1067.json.bz2'].id"

# Check vulnerabilities for UBI 8 SBOM
GET http://localhost:8080/api/v2/sbom/{{ubi8_sbom_id}}/advisory

HTTP 200

[Asserts]
jsonpath "$[?(@.document_id == 'CVE-2023-44487')].status[?(@.context.cpe == 'cpe:/a:redhat:enterprise_linux:8:*:crb:*')]" count == 1
jsonpath "$[?(@.document_id == 'CVE-2023-44487')].status[?(@.context.cpe == 'cpe:/o:redhat:enterprise_linux:8:*:baseos:*')]" count == 1
