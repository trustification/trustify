# Importer

The importer is responsible for importing documents into the system.

Module level documentation: [modules/importer/README.md](../../modules/importer/README.md)

## Entities

```mermaid
erDiagram

IMPORTER only one to zero or more IMPORTER_REPORT : owns

IMPORTER {
    string name PK
    uuid revision

    state state
    json configuration
}

IMPORTER_REPORT {
    uuid id PK
    string importer FK
    string error
    json report
}
```

## Services

```mermaid
classDiagram

IngestorService <|-- ImporterService

class IngestorService {
    +ingest_sbom(SBOM)
    +ingest_advisory(SBOM)
}

class Importer {
    +string name
    +uuid revision

    +state state
    +timestamp? last_change
    +timestamp? last_run
    +timestamp? last_success
    +string? last_error

    +ImporterConfiguration configuration
}

class ImporterConfiguration {
    +json value
}

class ImporterService {
    +create(name, ImporterConfiguration)
    +Importer read(name)
    +delete(name, revision?)

    +update_configuration(name, ImporterConfiguration, revision?)
    +update_start(name)
    +update_finish(name, report)

    +Vec~Importer~ list()
    +Vec~ImporterReport~ get_reports(name)
}
```

```mermaid
sequenceDiagram

loop
    ImporterService ->> ImporterConfig: wait for next pending job
    ImporterConfig -->> ImporterService: next job
    loop
        ImporterService ->> Source: fetch next document
        Source -->> ImporterService: next document
        ImporterService ->>+ IngestorService: store document
        IngestorService -->>- ImporterService: finished
    end
    ImporterService ->> ImporterReport: store report
end
```
