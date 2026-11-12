# Programs

The programs and folders of this repository, with their flags. Back to the [README](../README.md).

## cmd/services

- `cmd/services -service inventory|orders|reports|support -secret-file <service.secret>` runs a Fetch business API, with independent authenticated receipts, state and reset.

### Receipts and addresses

- A service holds its newest 10,000 receipts; `GET /receipts` on the control listener lists them oldest first with `dropped`, the number of older ones let go since the last reset.
- Defaults honor `EAT_PORT_OFFSET`; `-listen` and `-control` select explicit loopback addresses.
- Orders uses `-inventory <http-origin>` and Reports uses `-orders <http-origin>` for authenticated internal calls.

### TLS

- With `-tls-cert`, `-tls-key` and `-client-ca` (all three, or none) the API serves TLS and admits only clients presenting a certificate issued by that CA; only then may `-listen` name an address other than loopback.
- Inventory and Orders then also answer their `/internal/` endpoints, and nothing else, on `127.0.0.1` at the same port, where the other services' calls arrive.
- The control listener is always loopback.
- Accounts takes the same TLS flags.

### Gateway assertion

- `-gateway-key <file>` (the JSON Web Key Set that `apiward jwks` prints; Accounts takes it too) makes the API answer only requests carrying the gateway's signed `X-Gateway-Assertion` made for this service, valid for its 30 seconds with 5 seconds of clock difference allowed, and read the account and roles from it instead of `X-Gateway-Subject` and `X-Gateway-Roles`; anything else is answered `401 gateway_assertion_required`, while `/internal/` calls keep using the service key.
- `demo up` on one machine creates the gateway's assertion key and starts the four APIs with its key set (Accounts stays directly reachable, as the demo commands sign in there); delete `assertion-keys.json` from the state folder and restart to let the APIs answer direct requests again, as the standalone condition of `cmd/measure` needs.
- The two-host and container setups always require the assertion: `demo certs` writes the gateway's assertion key into the `gateway` folder and its key set into the `fetch` folder, and `demo up -role fetch` starts the four APIs with it, so a client certificate alone no longer reaches an API.
- The assertion must also name the request's own method and path.

### Built-in protection

- `-local-security <folder>` turns on built-in protection ([modes.md](modes.md)) with the trusted keys and blocked list in that folder; without it the API trusts the identity headers a gateway sets.

## cmd/accounts

- `cmd/accounts -secret-file <service.secret> -signing-settings <accounts.json>` runs Fetch Accounts.
- Signing settings contain `kid` and an absolute `private_key_file`.
- Only Accounts signs application tokens, which last 15 minutes.
- Account and signing secrets stay in the private demonstration state.

## cmd/demo

- `cmd/demo` builds, sets up and runs the full local stack with `up`.
- `up -role fetch -programs <folder>` runs the services, Accounts and shop already built in that folder instead of building them, as the container image does; `-measure` adds measurement mode, where each service keeps only answer counts per status with no cap (`GET /receipts` on its control listener) and Accounts and Orders also seed the customers `load-0001` to `load-1000` (`load0001@fetch.test`, demo password, full wallet), and Orders and Inventory keep their data from growing (Orders holds its seed orders and the newest 1,000 to 2,000 placed ones; checkout and reservation identities older than the newest 10,000 are forgotten and could be used again), so a long load run costs the same per request at its end as at its start and is not cut short by one account's rate limit; `prepare` gives a new gateway started from the APIWard image its administrator and baseline; `health` succeeds once every Fetch service on the host answers, the image's health check.
- `setup` writes `gateway.json`, complete baseline and deny-all policies, `service.secret`, a signing key pair and `accounts.json` into a new identified private directory, then installs the first administrator.
- `run` starts the five services and the gateway, serves the shop's built files on the website upstream, reports protected admission separately from listening, and stops its own children gracefully.
- `token` is an optional client of Accounts for a seeded subject; it cannot change the fixed 15-minute lifetime.
- `reset` restores every service's seed and clears its receipts.
- `events` prints request events from the gateway's active audit file; retained rotated files are not searched.

## cmd/measure

- `cmd/measure -samples 30 -account cust-001 [-builtin-offset N]` collects preliminary serial wallet latency against an isolated running stack: standalone (Orders called directly), behind APIWard, and with `-builtin-offset` also a `demo up -local` stack started with `EAT_PORT_OFFSET=N`, in rotating order so no condition always goes first. It honors `EAT_PORT_OFFSET`, keeps credentials out of output, checks equivalent successful responses, and emits raw observations and aggregate JSON.

## Other folders

- `internal/services`: the four APIs and Accounts, and every API's operation table (roles, rates, request bodies), which is also the gateway baseline. `internal/guard`: built-in protection. `internal/ports`: the demonstration addresses.
- `client/`: the shop (React and TypeScript, built with Vite) and its browser tests; see `../client/README.md`. `e2e/`: the browser-test helpers shared with APIWard's Dashboard tests. `openapi/`: an OpenAPI description of each API.
