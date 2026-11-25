# Programs

The programs and folders of this repository, with their flags. Back to the [README](../README.md).

## cmd/services

- `cmd/services -service inventory|orders|reports|support -control-secret <service.secret> -keys <folder>` runs a Fetch business API, with independent authenticated receipts, state and reset.

### Receipts and addresses

- A service holds its newest 10,000 receipts of API requests and, apart, its newest 10,000 of internal calls (marked `internal`), so a report's page reads never push out API receipts; `GET /receipts` on the control listener lists both oldest first with `dropped`, the number of older ones let go since the last reset.
- Defaults honor `EAT_PORT_OFFSET`; `-listen` and `-control` select explicit loopback addresses.
- Orders uses `-inventory <http-origin>`, and Reports and Support use `-orders <http-origin>`, for authenticated internal calls.
- `-control-secret` names the bearer secret of the control listener only; it opens no internal endpoint.
- `-keys` names the folder of the internal call keys, one `<service>.key` per calling service: Orders, Reports and Support each send their own key in `X-Service-Key`.
- A service reads only the keys it holds: its own when it calls another service, and the key of each service that calls it (Inventory: `orders.key`; Orders: `orders.key`, `reports.key`, `support.key`; Reports: `reports.key`; Support: `support.key`).
- A callee knows the caller by its key and admits only the calls it makes: Orders at every Inventory internal endpoint, Reports at `GET /internal/orders`, Support at `GET /internal/orders/<id>`; another caller's key is `401 service_key_required`, a known caller at another endpoint `403 service_not_permitted`.
- A service refuses to start with a missing, extra, short or shared key.
- The control secret and each key file must be a regular file; on Unix it must be readable by its owner only (mode 600) and belong to the service's user or root.
- Started with neither `-local-security` nor `-gateway-key`, a service says on start that it is standalone (unprotected) and trusts the identity headers as sent.
- `POST /reset` on the control listener clears the data and the receipts; the service writes a line to its log (standard error) first.
- A checkout's `Idempotency-Key` is kept at least a day while the service runs, so a retry replays the first answer; a server failure (5xx) is not kept, so a retry tries again.
- Keys live in memory only: a restart or `POST /reset` forgets them, and a retry after it places a new order.
- A service's key memory holds at most 32 MiB of stored answers; past it the oldest are forgotten when old enough, and otherwise a new keyed checkout is answered `503 checkout_busy`.
- A rejected checkout (4xx after it ran, such as `insufficient_wallet`) is kept and replayed like a success, as Stripe does for requests that began executing; send a new key after fixing the cause.
- Order lists are newest placed first; `/orders/merchant` pages like the other lists (`limit` 1 to 100, default 50 here and 20 elsewhere; `next` names the `after` cursor of the next page).
- An order list answer copies no other request's data and is encoded after the service lock is released; reads share the lock, so a long read never holds up another.
- A compensation that Inventory did not confirm (a stock release) is retried by a worker of its own, every second and backing off to 30 seconds while it fails, never by another request.
- Order numbers continue after the seed's highest.
- The seed orders cover the 86 days ending two days before the service started, and four recent orders the day before, so the default 90-day report always shows them; every reset in one run gives the same seed.
- Support keeps its newest 1,000 tickets, each with at most 20 messages; a reply past that is answered `409 ticket_full`.
- `/support/mine` and `/support/queue` page (`limit` default 50, `next`, `after`) and list ticket summaries: `message_count`, a `preview` of the last message (120 characters) and `updated_at`; the messages come only from `/support/ticket/{id}`.
- A ticket's `order` must be one of the customer's own orders, checked with Orders once when the ticket is opened: another customer's or an unknown order is answered `422 invalid_order`, and an Orders outage `503 orders_unavailable`.
- Support bodies may be up to 16 KiB, so every field fits at its declared length in any UTF-8 text.

### TLS

- With `-tls-cert`, `-tls-key` and `-client-ca` (all three, or none) the API serves TLS and admits only clients presenting a certificate issued by that CA; only then may `-listen` name an address other than loopback, and then it must.
- Inventory and Orders then also answer their `/internal/` endpoints, and nothing else, on `127.0.0.1` at the same port, where the other services' calls arrive; the TLS listener answers no `/internal/` path.
- On Unix the TLS key must be readable by its owner only, and the certificate and client CA not writable by the group or others; each must belong to the service's user or root.
- The API certificate, key and client CA reload automatically when any file's size or modification time changes (checked at most once a second); a failed reload keeps the previous files and logs the error.
- Every API listener reads at most 64 KiB of request headers, and a request body only for POST, PATCH and PUT, up to the largest body its operations take.
- The control listener is always loopback.
- Accounts takes the same TLS flags.

### Gateway assertion

- `-gateway-key <file>` (the JSON Web Key Set that `apiward jwks` prints; Accounts takes it too and requires the assertion for `refresh` and `me`, while signing in needs none) makes the API answer only requests carrying the gateway's signed `X-Gateway-Assertion` made for this service, valid for its 30 seconds with 5 seconds of clock difference allowed, and read the account and roles from it instead of `X-Gateway-Subject` and `X-Gateway-Roles`; anything else is answered `401 gateway_assertion_required`, while `/internal/` calls keep using the caller's key.
- `demo up` on one machine creates the gateway's assertion key (Ed25519, so the gateway signs EdDSA) and starts the four APIs and Accounts with its key set (signing in at Accounts stays directly reachable, as the demo commands sign in there); delete `assertion-keys.json` from the state folder and restart to let the APIs answer direct requests again, as the standalone condition of `cmd/measure` needs.
- The two-host and container setups always require the assertion: `demo certs` writes the gateway's assertion key into the `gateway` folder and its key set into the `fetch` folder, and `demo up -role fetch` starts the four APIs with it, so a client certificate alone no longer reaches an API.
- The assertion must also name the request's own method and path, and the issuer `apiward`.
- An assertion can be replayed on the same method and path until it expires, at most 35 seconds; there is no one-time memory. Reading one needs the gateway-to-service connection, which mutual TLS protects in the two-host setup.
- On Unix the key set file must not be writable by the group or others and must belong to the service's user or root.
- The gateway key set reloads automatically when the file's size or modification time changes (checked at most once a second); a failed reload keeps the previous keys and logs the error.
- Refused assertions are written to the service's log, at most one line a second with the reason and the number refused since the last line.

### Built-in protection

- `-local-security <folder>` turns on built-in protection ([modes.md](modes.md)) with the trusted keys and blocked list in that folder; without it the API trusts the identity headers a gateway sets.
- With it, `-local-security-archive <absolute folder>` (default `archive` in that folder) is where rotated security log files are compressed, `-local-security-archive-bytes` (default 2 GiB, at least 64 MiB) bounds them, and `-local-security-when-full` is `evict_oldest` (default: the oldest file is deleted after a record of it) or `refuse` (nothing is deleted; requests are refused once the log folder is full).

## cmd/accounts

- `cmd/accounts -control-secret <service.secret> -signing-settings <accounts.json>` runs Fetch Accounts; it makes and takes no internal calls, so it refuses `-keys`.
- The signing key is parsed once and reloaded when `accounts.json` or the key file changes (size or modification time); on Unix the settings must not be writable by the group or others and the key must be readable by its owner only.
- Password hashing and token signing run outside the service lock, so sign-ins use several processors and never hold up other requests.
- Signing settings contain `kid` and an absolute `private_key_file`.
- Only Accounts signs application tokens, which last 15 minutes.
- Account and signing secrets stay in the private demonstration state.

## cmd/demo

- `cmd/demo` builds, sets up and runs the full local stack with `up`.
- `up -role fetch -programs <folder>` runs the services, Accounts and shop already built in that folder instead of building them, as the container image does; `-measure` adds measurement mode, where each service keeps only answer counts per status with no cap (`GET /receipts` on its control listener) and Accounts and Orders also seed the customers `load-0001` to `load-10000` (`load0001@fetch.test`, demo password, full wallet), and Orders and Inventory keep their data from growing (Orders holds its seed orders and the newest 1,000 to 2,000 placed ones; checkout and reservation identities older than the newest 10,000 are forgotten at any age and could be used again, and a forgotten reservation returns its stock); outside measurement mode the same bounds are 5,000 to 10,000 orders and 50,000 identities, and a checkout identity is forgotten only once a day old (at 200,000 younger ones a new keyed checkout is answered `503 checkout_busy`), below the 20,000 orders a report reads, so a long load run costs the same per request at its end as at its start and is not cut short by one account's rate limit; `prepare` gives a new gateway started from the APIWard image its administrator and baseline; `health` succeeds once every Fetch service's control listener on the host answers HTTP as that service (its refusal of a request without the control secret), the image's health check.
- `setup` writes `gateway.json`, complete baseline and deny-all policies, `service.secret`, a signing key pair and `accounts.json` into a new identified private directory, then installs the first administrator.
- `run` starts the five services and the gateway, serves the shop's built files on the website upstream (read once at start; browsers revalidate each file by its ETag), reports protected admission separately from listening and every later change of it, and stops its own children gracefully.
- `token` is an optional client of Accounts for a seeded subject; it cannot change the fixed 15-minute lifetime.
- `up -role fetch -standalone` serves the APIs on the `-bind` address with nothing checked but the client certificate: they believe the identity headers a client sends. It exists to measure the unprotected floor; never use it to protect anything.
- `up -role fetch -local` serves them on the `-bind` address with built-in protection ([modes.md](modes.md)), trusting the key Accounts signs with from the `-certs` folder.
- Neither takes the gateway's assertion key, and each works with `-measure`.
- Without a gateway the banner names no shop address: the shop's pages load there, but nothing routes their API calls.
- `up -role fetch` refuses a `-certs` folder whose server certificate does not name `-bind`, was not issued by the folder's CA, or expires within a day; `up -role gateway` checks its client certificate the same way.
- `tokens -accounts IP:PORT -certs <gateway folder> -out F` signs in `load-0001` to `load-10000`, Merchant 5 and Merchant 6 at Accounts on this host and writes their tokens to the new file `F` (mode 600; an existing file is refused) for a load run; `load-1000` is the account a run sends over its rate, the others are its customers; `-customers N` signs in only the first N customers (default all 9,999): each sign-in costs Accounts a password hash (64 MiB, on up to half the processors at once; a sign-in that waits more than 2 seconds for one is answered `503 accounts_busy` with `Retry-After: 1`) and tokens live 15 minutes, so sign in only what a run needs (the load script's `CUSTOMERS` must match).
- It connects from `127.0.0.1` with the gateway's client certificate and names a different visitor (`198.18.0.0/15`, the benchmarking range) for each sign-in, so built-in protection counts each one separately; it checks that the CA of the folder issued the server's certificate for the `-accounts` address, or for `-name NAME` when the certificate names another one.

## load

- `load/run.js` is a k6 run of a mix at a constant arrival rate: `MODE=gateway` through the gateway, `local` straight to each API with the caller's token (built-in protection), `direct` straight to each API with identity headers (nothing checked).
- Tokens come from the file `demo tokens` wrote (`TOKENS`), so sign-in is never timed.
- The n-th request takes the n-th class of a cycle that spreads the classes by share, and the n-th account of a seeded shuffle, so no account's rate depends on chance.
- `STEPS` (comma-separated rates) with `STEP` (duration) runs a capacity ramp instead of one rate; the header of `run.js` lists every setting.
- Mixes: `mix.json` (`fetch-mix-1`, every class), `poster.json` (signed-in reads and the checkout, which answer the same in every mode) and `security.json` (that mix plus refusals, for modes with checks).
- `reset` restores every service's seed and clears its receipts.
- `events` prints request events from the gateway's active audit file (`-last` 1 to 10,000); retained rotated files are not searched.
- `run` says at start when the state folder has no `assertion-keys.json`, as the APIs then answer direct requests.

## cmd/measure

- `cmd/measure -samples 30 -account cust-001 [-builtin-offset N]` collects preliminary serial wallet latency against an isolated running stack: standalone (Orders called directly), behind APIWard, and with `-builtin-offset` also a `demo up -local` stack started with `EAT_PORT_OFFSET=N`, in rotating order so no condition always goes first. It honors `EAT_PORT_OFFSET`, keeps credentials out of output, checks equivalent successful responses, and emits raw observations and aggregate JSON.

## Other folders

- `internal/services`: the four APIs and Accounts, and every API's operation table (roles, rates, request bodies), which is also the gateway baseline. `internal/guard`: built-in protection. `internal/ports`: the demonstration addresses.
- `client/`: the shop (React and TypeScript, built with Vite) and its browser tests; see `../client/README.md`. `e2e/`: the browser-test helpers shared with APIWard's Dashboard tests. `openapi/`: an OpenAPI description of each API.
