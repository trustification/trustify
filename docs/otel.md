# OpenTelemetry

[OpenTelemetry](https://opentelemetry.io/) is an observability framework for collecting, generating,
and exporting telemetry data (traces, metrics, and logs, aka [signals](https://opentelemetry.io/docs/concepts/signals/))
to improve system monitoring and performance. It is a [CNCF project](https://www.cncf.io/projects/opentelemetry/),
ensuring vendor-neutral and standardized observability solutions for cloud-native applications.

[Jaeger](https://www.jaegertracing.io/), [Grafana Tempo](https://grafana.com/oss/tempo/) and [Prometheus](https://prometheus.io/) are also CNCF projects for observability.
Jaeger and Grafana Tempo focuses on distributed tracing, while Prometheus handles metrics and monitoring.

The OpenTelemetry Collector (aka OTELCOL or OTEL collector) is a vendor-neutral service for
processing and exporting telemetry data, that also acts as a facade for both Jaeger and Prometheus,
enabling a clear separation of roles: developers focus on instrumenting applications and sending data to the Collector,
while DevOps manage its configuration, deployment, and backend integrations.

> [What is Observability?](https://www.brendangregg.com/blog/2021-05-23/what-is-observability.html)

> Observability: The ability to observe.

We are focusing on the signals: traces and metrics.

## To enable traces, follow the instructions below

* Clone trustify
* Open a terminal and run:

### Tempo

```shell
podman compose -f etc/telemetry/compose-tempo.yaml up
```

> This will start the OTEL Collector, and Tempo

### Jaeger

```shell
podman compose -f etc/telemetry/compose.yaml up
```

> This will start the OTEL Collector, Jaeger and Prometheus

* Open a new terminal and run:

```shell
podman compose -f etc/deploy/compose/compose.yaml up
```

> This will start the database

* Open a new terminal and run:

```shell
RUST_LOG=info OTEL_TRACES_SAMPLER_ARG=1 cargo run --bin trustd api --db-password trustify --auth-disabled --tracing enabled
```

> This will start trustify api with traces enabled. For the importer, use the command bellow:


```shell
RUST_LOG=info OTEL_TRACES_SAMPLER_ARG=1 cargo run --bin trustd importer --db-port 5432 --tracing enabled
```

Access Trustify at [localhost:8080](http://localhost:8080) and analyze the traces using the [Jaeger UI](http://localhost:16686/) or [Tempo](http://localhost:3000/)

## To enable metrics, follow the instructions below

* Clone trustify
* Open a terminal and run:

```shell
podman compose -f etc/telemetry/compose.yaml up
```

> This will start the OTEL Collector, Jaeger and Prometheus

* Open a new terminal and run:

```shell
podman compose -f etc/deploy/compose/compose.yaml up
```

> This will start the database


* Open a new terminal and run:

```shell
cargo run --bin trustd api --db-password trustify --auth-disabled --metrics enabled
```

> This will start trustify api with metrics enabled


Access Trustify at [localhost:8080](http://localhost:8080) and analyze the metrics using the [Prometheus UI](http://localhost:9090/)

To view Trustify's metrics in Prometheus, use the following query `{exported_job="trustify"}` and click execute button.
