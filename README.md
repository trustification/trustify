## dev-env

Starting:

```shell
podman-compose -f deploy/compose/compose.yaml up
```

Connect to PSQL:

```shell
env PGPASSWORD=eggs psql -U postgres -d huevos -h localhost -p 5432
```

