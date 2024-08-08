# GraphQL API for trustify

The graphql API is available from the web service through the `/graphql` endpoint

## Advisory Queries

Fetch all advisories and each related organization and vulnerabilities :
`curl -s localhost:8080/graphql -H "Content-Type: application/json" -d '{ "query": "{ getAdvisories { id identifier location sha256 published organization { id website } vulnerabilities { id identifier title }}}" }' `

Fetch an advisory by id and get its related organization and vulnerabilities :
`curl -s localhost:8080/graphql -H "Content-Type: application/json" -d '{ "query": "{ getAdvisoryById(id: 1) { id identifier location sha256 published organization { id website } vulnerabilities { id identifier title }}}" }'`

Fetch all advisories :
`curl -s localhost:8080/graphql -H "Content-Type: application/json" -d '{ "query": "{ getAdvisories { id name  issuerId }}" }' `

## Vulnerability Queries

Fetch all vulnerabilities :
`curl -s localhost:8080/graphql -H "Content-Type: application/json" -d '{ "query": "{ getVulnerabilities { id identifier published withdrawn }}" }' `

## Fetch a vulnerability by identifier :

`curl -s localhost:8080/graphql -H "Content-Type: application/json" -d '{ "query": "{ getVulnerabilityById(identifier: \"CVE-2024-28111\") { id identifier published withdrawn }}" }' `

## Organization Queries

Fetch an organization by name :
`curl -s localhost:8080/graphql -H "Content-Type: application/json" -d '{ "query": "{ getOrganizationByName(name: \"org1\" ) { id name cpeKey website}}" }' `

## SBOM Entity Queries

Fetch all SBOMs by location :
`query Sboms_by_location {sbomsByLocation(location: "1") {sbomId, location, sha256, authors}}`

Fetch a SBOM by Id :
`query OneSbom {getSbomById(id:"4ad38204-b998-4054-8ddc-a5c94ec37aa9") {sbomId, location, sha256, authors}}`
