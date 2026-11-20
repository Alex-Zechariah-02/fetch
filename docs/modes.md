# Running without the gateway, and moving behind it

Back to the [README](../README.md).

## Standalone (unprotected)

```
go run ./cmd/demo up -standalone
```

- Runs the shop, the four APIs and Accounts with no gateway, to show the application before it is protected.
- It needs no APIWard checkout.
- The demo process listens on the shop's address (`http://127.0.0.2:9480/`), serves the shop and forwards each API path to its service.
- **Nothing is checked:** it copies the `sub` and `roles` claims of any bearer token into the identity headers the services read, without verifying the token, so a token with made-up roles is believed; only identity headers sent by the client are discarded.
- Never use this mode to protect anything.
- Each run makes a new folder `standalone` in the demo home with a new signing key; tokens from an earlier run stop working.
- `-fresh` and `-apiward` are refused with `-standalone`.

## Built-in protection

```
go run ./cmd/demo up -local
go run ./cmd/demo block -local [-unblock] cust-002
```

### What each API checks

- Runs the shop, the four APIs and Accounts with no gateway, each API checking every request itself before its handler runs: the RS256 token Accounts issued (one `Bearer` field, header members `alg`, `kid` and `typ` only, issuer `fetch-accounts`, audience `fetch-gateway`, expiry and not-before with 60 s leeway, as the gateway allows by default), the roles its own operation table permits, a blocked-accounts list, a weighted sliding-window rate per operation (per account, or per client address for public operations), and the request body's size, media type, strict JSON and schema.
- Before the handler runs, each API writes the admission to its own security log (`<api>-security.log`) and waits until the file is synced; if it cannot, the request is refused with 503. Outcomes and control refusals (token, roles, blocked account, rate, body) are logged one record each.
- Refusals no control decides (a target not in origin form, a tunnel or upgrade, a path that is not canonical, no such path or method, overload) are counted instead, as the gateway does: one `audit.ingress_summary` record a minute with the counts by reason and the 16 busiest client addresses.
- Past 1,024 requests in flight an API refuses `503 overloaded` with `Retry-After: 1` before checking the token (the gateway's default `data.max_in_flight`).
- A public operation counts an IPv6 client by its /64 (the gateway's default `ipv6_rate_prefix`); the log keeps the exact address.
- A rate refusal (429) carries `Retry-After` with the seconds until the next request is admitted; every 503 carries `Retry-After: 1`.
- An API holds at most 32,768 rate counters (the gateway's default `rate_counters`); a full table refuses a new key `503 gateway_unavailable`.
- `GET /guard` on the API's control listener reports the requests in flight, overload and full-table refusals, rate counters held, records lost and the log's size.
- Each security log rotates at 64 MiB to a name holding the UTC time (`<api>-security-2026-11-20T08-22-33.123.log`), as the gateway's does. A background task compresses each rotated file (gzip, `.log.gz`) into the archive folder, records `log.archived` and only then deletes the original.
- Each API's archive holds at most 2 GiB (`-local-security-archive-bytes`), so the five APIs together keep the gateway's default 10 GiB; over that, the oldest file is deleted after a `log.evicted` record (name, size, SHA-256, first and last record times). The log folder keeps at most 8 × 64 MiB not yet archived.
- Below 10 % free space on the log or archive disk the oldest files are evicted early, each recorded first. A 64 MiB reserve file (`<api>-security.reserve`) is released when a write finds the disk full, so records are still saved while files are evicted; it is made again a minute later once there is room.
- A failed write or sync replaces the active file without a restart: the batch is refused, the file is kept under its rotated name, and `log.recovered` (reason `sync_failed`) names it; a full disk with no reserve left refuses requests and is retried once a second (`log.recovered`, reason `storage_space`). Requests are refused only while no record can be saved.
- `-local-security-when-full refuse` deletes nothing: archiving stops at the archive's bound, and once the log folder is full every request is refused until files are moved away.
- If the archive folder fails (full, missing, no permission), files are compressed in the log folder instead and move once it works. `GET /guard` on the control listener reports `log_archive_ok`, `log_archive_bytes`, `log_pending_files`, `log_free_bytes`, `log_reserve_bytes`, `log_evictions`, `log_recoveries` and `log_slow_saves` (saves over 100 ms).
- Sizing (measured, 750 requests/s with refusals, WSL 2): the busiest API writes about 0.48 MiB/s; a 64 MiB file compresses to about 3.9 MiB (ratio 16.6), so 2 GiB holds about 520 files, about 19 hours at that rate.
- A logged method is cut at 32 bytes and a path at 512.
- A failed write (for example a full disk) refuses every later request of that API with 503 until it is restarted; each run starts empty logs in a new folder (see below).
- Identity headers sent by a client are discarded, and Accounts verifies the token itself for `refresh` and `me`.
- Refusals use the services' error form with the gateway's codes (`unauthenticated`, `forbidden`, `account_blocked`, `rate_limited`, `bad_request`, `payload_too_large`, `unsupported_media_type`, `overloaded`).

### How it runs

- The demo process only routes each API path to its service with the caller's token, and names the caller in `X-Forwarded-For`.
- An API trusts that header only from a peer on the same host (the demo process), so its public limits count each visitor; any other peer counts as itself.
- Each run makes a new folder `local` in the demo home with a new signing key, the public key file every API trusts (`keys.json`), an empty `blocked.json` and the security logs.
- `block -local` replaces `blocked.json` whole and then each running API's list through its control listener; every API is tried and each one that did not take the list is named.
- An API writes each list it takes to `blocked.json` (a new file renamed over the old, then synced) before it is in force, so an API restarted within a run keeps it; the next `up -local` starts a new folder with no blocked account.
- Changing a role, a rate or a schema means editing `internal/services/rules.go` and restarting the APIs; a new signing key means restarting every API.
- `demo up -role fetch -local` runs the same checks on a Fetch host's `-bind` address over TLS, without the demo's proxy, for measurements ([programs.md](programs.md)).

## Moving the APIs behind APIWard

- Each API has an OpenAPI 3.1 description in `openapi/`: `inventory`, `orders`, `reports`, `support` and `accounts` `.openapi.yaml`.
- They describe the endpoints, sign-in, query parameters and request bodies, and carry Fetch's own `x-fetch-roles` and `x-fetch-access` members.
- APIWard's schema checks cover headers and request bodies, not query parameters: the import report lists each query parameter as not enforced, and the service itself refuses an unknown or invalid one (`400 invalid_query`).
- APIWard's import passes `x-fetch-*` members through unread and takes no roles or rate limits from a description, so an administrator sets those in the Dashboard.

```
go run ./cmd/demo migrate -out <new-policy-file>
go run ./cmd/demo policy stage -dir <home>/state -file <new-policy-file>
```

`migrate` builds the gateway from the APIWard checkout and runs `apiward policy import-openapi` once per API, onto a base that holds the services' addresses, the roles and the shop's pages, and writes one policy file; it stops if any endpoint is refused. Staging saves it as a draft change in the running gateway; in the Dashboard, give each endpoint its roles and rate limit, put the change on trial and keep it. `-openapi <folder>` reads the descriptions from another folder, such as a copy from the Fetch host; `-fetch <ip>` builds onto a gateway host's base, whose services are on the Fetch host over TLS ([hosts.md](hosts.md)), and the file is then staged with `-dir <home>/gateway`. On any other gateway, copy the descriptions there and run `apiward policy import-openapi` directly; it reads only the files it is given.
