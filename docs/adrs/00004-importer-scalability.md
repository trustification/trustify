# 00004. Importer Scalability in Trustify

Date: 2025-02-14

## Status

Draft

## Context

This ADR is concerned with our ability to scale the importer processes
that ingest documents -- SBOM's and advisories -- from various
sources.

Currently, the importer process iterates over the enabled importer
definitions in the database sequentially, running each according to
its schedule. Executing more importer processes results in redundant
work, each of them doing the same thing, i.e. there is no coordination
to distribute the load among them.

### Requirements

* The work should be distributed -- no two importer processes should
  be doing the same work.
* The solution should be fault-tolerant -- importer instances may come
  and go -- any work in process by a crashed/killed one must be
  eventually picked up by another.
* In short, adding an importer process should increase the ingestion
  throughput, i.e. the system should be scalable.

## Decision

Since trustify already depends on PostgreSQL -- the import definitions
persist there -- we can persist the "coordination state" there, too.

Two columns can be added to the `IMPORTER` table:
* `runner` -- a string identifying the instance currently running the
  import, e.g. `{hostname}+{PID}`
* `heartbeat` -- a timestamp regularly updated by the runner to
  indicate it's still alive while processing the job.

Each importer process will identify rows in the table representing
jobs ready to be run by not only comparing the `last_run` field to the
configured schedule, but also that there is no current `runner`
associated with the job or the current runner hasn't recently updated
its `heartbeat`.

Once a row has been identified, the importer process will
optimistically lock it by attempting to update the `runner` field with
its own identifier, e.g.

```
  UPDATE importer SET runner = 'foo.com+12345' WHERE name = 'cve' AND runner IS NULL
```

If the update succeeds, the runner should then regularly update
`heartbeat` while processing the job. A failed update indicates some
other instance took the job.

Once the job is complete, the runner is expected to set both fields
back to NULL, making the row available to other importer processes
when the schedule fires again.
