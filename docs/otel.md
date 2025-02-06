# OpenTelemetry

## Sending traces to OpenTelemetry Collector at development time

Jaeger and OTEL Collector:

```shell
podman compose -f etc/telemetry/compose.yaml up
```

Database:

```shell
podman compose -f etc/deploy/compose/compose.yaml up
```

Trustify with traces:

```shell
OTEL_TRACES_SAMPLER_ARG=1 OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317" cargo run --bin trustd api --db-password trustify --auth-disabled --tracing enabled
```

Importer with traces:

```shell
RUST_LOG=info OTEL_TRACES_SAMPLER_ARG=1 OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317" cargo run --bin trustd importer --db-port 5432 --tracing enabled
```

Access Trustify at [localhost:8080](http://localhost:8080) and analyze the traces using the [Jaeger UI](http://localhost:16686/)

## Gathering metrics at development time

Prometheus and OTEL Collector:

```shell
podman compose -f etc/telemetry/compose.yaml up
```

Database:

```shell
podman compose -f etc/deploy/compose/compose.yaml up
```

Trustify with metrics:

```shell
cargo run --bin trustd api --db-password trustify --auth-disabled --metrics enabled
```

Access Trustify at [localhost:8080](http://localhost:8080) and analyze the metrics using the [Prometheus UI](http://localhost:9090/)
