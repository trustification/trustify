# 00001. Graph Analytics in Trustify

Date: 2024-08-26

## Status

Draft

## Context

This ADR is concerned with how we might answer the following questions: 

**_Which 'package' should I (engineer) fix ?_**

This roughly translates to:

1) Find a component(s) by its purl, name or glob/regex
2) Resolve each component(s) ancestors
3) The top most ancestor will be its root component

Product security engineers often do not know the fully qualified component name and will need to 'glob' search on some string to 
ensure they retrieve all related components.

For example,

![Simple sbom](sbom-simple-example.png)

has 3 root components (A,AA,EE) ... querying from the context of any other node should resolve to the appropriate root component.


**_I (user) want to know which 'products' contains a component ?_**

This roughly translates to:

1) Find a component(s) by its purl, name or glob/regex
2) Resolve each component(s) ancestors
3) The top most ancestor will be its root component
4) Determine product relationship of the root component(s)

### Requirements

* Given a component/package determine its ancestor components in dependency tree (aka root component(s)).
* Given a component/package determine its ancestor components in dependency tree (aka root component(s)) and determine their product relationships.

## Process flow

Graphs will be loaded 'lazily' eg. when they are requested.

1) retrieve list of _latest_ unique sbom ids searched by like or exact name. 
2) Using unique sbom ids, filter query package_relates_to_package (resolving left and right ID purl strings)
3) load into write locked hashmap<petgraph>, where the key is the sbom_id

Once a graph is loaded then query is
1) retrieve list of _latest_ unique sbom ids searched by like or exact name.
2) read only access on hashmap<petgraph>, looping through petgraphs performing ancestor node search
3) serialise results to REST API

## Decision

Generate a read only graph, using petgraph, which describes dependency relationships between components.

Each node of the graph will contain:
* component pURL
* component name
* published 

With the following possible edge relationships between components:
* ContainedBy
* GeneratedFrom
* PackageOf

Expose a set of REST API endpoints

**Retrieve a component(s) root component**
HTTP GET api/v1/analysis/root-component?q={}
HTTP GET api/v1/analysis/root-component/{component-name}
HTTP GET api/v1/analysis/root-component/{component-purl}

all of the above should return paginated lists:

```
{"total" : 2,
"items" : [
    {
        "purl": "pkg://rpm/redhat/libproxy-webkitgtk4@0.4.15-35.el9?arch=x86_64",
        "name": "libproxy-webkitgtk4",
        "published": "2024-07-30 19:22:06+00",
        "document_id": "https://access.redhat.com/security/data/sbom/spdx/MTA-6.2.Z",
        "product_name": "MTA-6.2.Z",
        "product_version": "6.2.z",
        "ancestors":[ .... ]
    },
    {
        "purl":"...",
        "name":"...",
        "published":"...",
        "product_name":"...",
        "product_version":"...",
        "ancestors":[...]
    } ...
]
}
```

where ancestors contain purl, name, published and document_id which answers our questions.

## Alternative approaches

We could query existing package_relates_to_package to resolve relationships though previous attempts with a pure SQL based
solution often experienced performance problems either due to 'join explosion' or need to constantly tweak indexes to accomodate 
performance of joins at scale.

We could use a graph datastore ... which dramatically simplifies everything as well as improving performance by at least a 
magnitude - though previous attempts have shown (especially at scale) that we need to either wait for postgres to natively 
support property graphs (as part of the new SQL standard) or use a commercial service (such as AWS neptune, Progress marklogic)
as there are currently no open source offerings that are fit for purpose (or available as part of our internal IT offerings). 
Using a graph database would also dramatically improve any kind of maintenance tasks for mutating or updating graph data directly.

## Consequences

We assume sbom data correctly enumerates dependency relationships - no attempt is made to 'fix up' (either at ingestion or query time)
with respect to generated read only graph. 

We assume equivalent Sbom SPDXID, across documents, imply equivalent pURL (aka component).

We assume Sbom SPDX identifiers are stable across multiple versions of the same document_id.

We assume products do not 'span' across multiple SBOM documents but that may not always be the case in the future.

Employing a read only graph avoids the challenges of having to maintain such a graph with inserts or updates (without a graph 
datastore this is always slow...).

We are mostly interested in answering these questions in the current context which implies the _maximum_ graph should only ever contain
relationships as defined in latest version of SBOMs. Answering this question in a historical context is out of scope (possible 
but much more complicated).

Loading and interrogating an 'in memory' graph has resource implications - it might be that this analytics process, at scale, will
need processing to be isolated (for example, as separate pod(s) in openshift). We might also have to consider connection specific
postgres configuration (and/or connect to a dedicated read only postgres replica).

Performance is limited by the fact we bespoke build a graph for each query ... we could optimise this approach by having 
a graph always available (loaded with latest version SBOM relationships). 