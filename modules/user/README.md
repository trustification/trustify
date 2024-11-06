# User management

## Store user preferences

This will create or replace the existing value.

```bash
http PUT localhost:8080/api/v1/userPreferences/foo key=value
```

## Get user preferences

```bash
http GET localhost:8080/api/v1/userPreferences/foo
```

## Delete user preferences

```bash
http DELETE localhost:8080/api/v1/userPreferences/foo
```

## Conditionally update user preferences

It is possible to update the value only if the expected precondition matches. Meaning that you can provide an
etag value as received from a `GET` or `PUT`, and the update will only take place if the revision/etag value hasn't
been changed yet by another update. If it did, the request will fail with a `412 Precondition failed` status and
appropriate action would be to re-fetch the data, apply the update again, and request another store operation. This
is also called "optimistic locking."

```bash
http PUT localhost:8080/api/v1/userPreferences/foo key=value 'If-Match:"<etag from get>"'
```

**NOTE:** Be sure that the `If-Match` value is actually quoted, e.g. `If-Match:"79e5d346-876f-42b6-b0d0-51ee1be73a4c"`
