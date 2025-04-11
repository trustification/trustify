# 00005. Upload API for UI

Date: 2025-04-11

## Status

ACCEPTED

## Context

When uploading a document, the request only returns once the document has been fully processed. This may take
several minutes.

Using HTTP, there is not always a clear indication if the request is still being processed, or if the connection is
stuck. Having ingress stacks, like OCP, AWS, etc., it is easy to run into "request timeouts" due to not having
reliable feedback on the HTTP channel.

To improve the situation for the UI, the idea is to create a stateful upload API. Allowing the requester to
initiate an upload, drop off the file on the backend side, and then offer some way to check for progres and outcome.

While this may work with any command line tool or custom client too, the intention is to design this API for the
UI (console) use case.

## Caveats

* There is some kind of state attached to this flow. It must be ensured that the client must not be aware of which
  backend instance to contact. So either it's not relevant due to some shared state. Or we implement something that
  allows it ending up in the right instance.
* We should think about security upfront. Only the requestor of an upload should be able to fetch information about the
  progres.

## Proposal

* We store the upload progress in a table
* We add an API allowing to query that table
* The backend process monitoring the upload needs to perform periodic updates to that table to keep the entry "fresh"
* Stale entries will periodically be cleaned up

### Database

The state table looks like this:

| Column  | Type                                   | Description                     | 
|---------|----------------------------------------|---------------------------------|
| id      | UUID                                   | Unique ID                       |
| updated | timestamp                              | Last update timestamp           |
| state   | enum { processing, failed, succeeded } | The state of the upload process |
| result  | JSON                                   | result response                 |

### REST API

* `GET /api/v2/upload/{id}`: Get information about the upload

  Response (`200 OK`):

  ```json5
  {
    "id": "opaque-unique-id",
    "state": "processing", // or failed, succeeded
    "updated": "2025-05-07T10:13:27Z", // always UTC,
    "result": {} // or absent for `processing`, `failed`
  }
  ```

* `DELETE /api/v2/upload/{id}`: Delete the state record, will not receive further updates

  Response (`204 No Content`): Sent if found or if not found.

* `POST /api/v2/upload`: Start an upload
  Request:
    * `format`: Format of the document, defaults to "auto-detect". Can also be `sbom` or `advisory`.
    * `watch` (default `false`): If present and `true`, the state tracking will be active. Otherwise, it will fall back to a
      synchronous upload, like the existing upload API. But unified for SBOM and advisory.
  
  Response (`202 Accepted`, `watch=true`):

   ```json5
   {
     "id": "opaque-unique-id",
     "format": "concrete-format" // e.g. "spdx"
   }
   ```
  
  Response (`201 Created`, `watch=false`):

  ```json5
  {
    "id": "document-id",
    "format": "evaluated format", // or provided
    "result": {}, // same as the state would have
  }
  ```

### Example flow: success

* Client initiates an upload on the specialized upload API (`POST /api/v2/upload?watch=true`)
    * The client stores the file in the storage
    * The backend adds an entry in the state table, using the digest returned by the storage as `id`
    * The backend spawns a task, periodically updating the `updated` timestamp
    * The backend returns the `id` and keeps processing the upload
* The client periodically checks the state using the returned `id` (`GET /api/v2/upload/{id}`)
  * The client can delete the state entry if it's no longer interested. Future updates will be discarded. 
* When the backend finished processing the upload
    * It sets the final `state` (`failed` or `succeeded`) and the `result`
    * It stops updating the `updated` column
* The backend cleans up (deletes) all entries with a "stale" `updated` timestamp

## Considerations

### Multiple backend instances

* Any backend can answer questions about the upload state, as the state is stored in the database
* All backends can clean up the upload state table, it is not important which instance does this

### Security

* The uploader will receive an ID to the update state, which is based on the file's content. Therefore, it can be
  assumed that the sender knows the content of the file and can know about the state of the upload too.
* The state will only be available during the time of the upload plus the timeout period for the entry

### Performance

* As the table only holds states for active uploads, the number of entries should be small. Queries happen by "primary
  id" and should be therefore fast.
* The upload process stores the file first. So it's not necessary to keep an additional copy in memory

### Format detection

In the process of this, we could also try to do some "format detection", allowing to use the same endpoint for
uploading any kind of document. However, I would see this as a stretch goal.

## Alternatives

* Keep the current API and deal with this on the HTTP, Ingress, Load Balancer side

  👎 Doesn't really solve the problem

* Find a way to not store the state in the database. One way to achieve this could be by using websockets as upload
  channel.

  👎 The downside of this is that it might be quite complex, and doesn't seem like a very common way of uploading things
  from the browser.

* Use the existing upload APIs and trigger this behavior with a flag.

  👎 The downside of this is that the response of the request varies based on the flag. Making the whole request more
  complex.

## Consequences

* Add a new upload state table
* Create REST API endpoints for initiating an upload and checking the state
