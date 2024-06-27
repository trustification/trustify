# trustify loadtest

Defines a set of simple [https://book.goose.rs/](goose load tests) against the web and rest endpoints.

## quickstart

Loads trustify endpoints with 3 concurrent users.
```
> cargo run --bin loadtest -- --host http://localhost:8080 -u 3
```
To stop load test hit [ctl-C], which should generate aggregate statistics.

Loads trustify endpoints against 10 concurrent users, generating an html report.
```
 cargo run --release -- --host http://localhost:8080  --report-file=report.html --no-reset-metrics -u 10
```
