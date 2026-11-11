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

- Runs the shop, the four APIs and Accounts with no gateway, each API checking every request itself before its handler runs: the RS256 token Accounts issued (one `Bearer` field, header members `alg`, `kid` and `typ` only, issuer `fetch-accounts`, audience `fetch-gateway`, expiry and not-before without leeway), the roles its own operation table permits, a blocked-accounts list, a weighted sliding-window rate per operation (per account, or per client address for public operations), and the request body's size, media type, strict JSON and schema.
- Before the handler runs, each API writes the admission to its own security log (`<api>-security.log`) and waits until the file is synced; if it cannot, the request is refused with 503. Refusals and outcomes are logged too.
- The security logs are never rotated or trimmed: a record is about 320 bytes, so an admitted request adds about 650 bytes (admission and outcome), about 1.2 GB per hour at 500 requests per second.
- A failed write (for example a full disk) refuses every later request of that API with 503 until it is restarted; each run starts empty logs in a new folder (see below).
- Identity headers sent by a client are discarded, and Accounts verifies the token itself for `refresh` and `me`.
- Refusals use the services' error form with the gateway's codes (`unauthenticated`, `forbidden`, `account_blocked`, `rate_limited`, `bad_request`, `payload_too_large`, `unsupported_media_type`).

### How it runs

- The demo process only routes each API path to its service with the caller's token.
- Every API's public limits therefore count the demo process's own address; measured traffic calls the APIs directly.
- Each run makes a new folder `local` in the demo home with a new signing key, the public key file every API trusts (`keys.json`), an empty `blocked.json` and the security logs.
- `block -local` changes `blocked.json` and then each running API's list through its control listener.
- Changing a role, a rate or a schema means editing `internal/services/rules.go` and restarting the APIs; a new signing key means restarting every API.

## Moving the APIs behind APIWard

- Each API has an OpenAPI 3.1 description in `openapi/`: `inventory`, `orders`, `reports`, `support` and `accounts` `.openapi.yaml`.
- They describe the endpoints, sign-in and request bodies, and carry Fetch's own `x-fetch-roles` and `x-fetch-access` members.
- APIWard's import passes `x-fetch-*` members through unread and takes no roles or rate limits from a description, so an administrator sets those in the Dashboard.

```
go run ./cmd/demo migrate -out <new-policy-file>
go run ./cmd/demo policy stage -dir <home>/state -file <new-policy-file>
```

`migrate` builds the gateway from the APIWard checkout and runs `gateway policy import-openapi` once per API, onto a base that holds the services' addresses, the roles and the shop's pages, and writes one policy file; it stops if any endpoint is refused. Staging saves it as a draft change in the running gateway; in the Dashboard, give each endpoint its roles and rate limit, put the change on trial and keep it. `-openapi <folder>` reads the descriptions from another folder, such as a copy from the Fetch host; `-fetch <ip>` builds onto a gateway host's base, whose services are on the Fetch host over TLS ([hosts.md](hosts.md)), and the file is then staged with `-dir <home>/gateway`. On any other gateway, copy the descriptions there and run `gateway policy import-openapi` directly; it reads only the files it is given.
