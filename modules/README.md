# Modules

Modules are features of trustify which seem to belong together.

Currently, we have:

* `graph` – The core graph model, correlation between the different SBOM and advisory entities.
* `ingestor` – Data ingestion functionality.
* `importer` – Scheduled data import management and execution. Uses `ingestor` for ingesting data.

There's an ideal (not enforced) layout of modules:

* `endpoints` — endpoints which can be mounted into an HTTP server instance using a `configuration` function
* `model` – a serializable data model which is used by the API (see `endpoints`)
* `service` – Services, which can be used as internal API.
* `server` – A server task which needs to run for certain functionalities of the module

The reason why `endpoints` is not covered by the `server` module is that this would mean that we could not create a
single HTTP server, serving all endpoints from a single HTTP port.
