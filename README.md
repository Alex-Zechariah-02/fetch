# Fetch

Fetch is a fictional food and grocery delivery application used to demonstrate and test [APIWard](https://github.com/Alex-Zechariah-02/apiward), a security policy gateway for REST APIs. It has a React shop in `client/`, four business APIs (Inventory, Orders, Reports, Support) and Fetch Accounts, which signs every application token. All accounts, merchants, items and orders are synthetic.

Behind APIWard, the shop is reached only through the gateway: its pages and assets are public `GET` operations of the API `web`, and every API call is checked, rate-limited and audited by the gateway's policy. The services keep their business rules (ownership, stock, wallet and order transitions) and trust the caller identity the gateway forwards.

## Layout

- `cmd/services -service inventory|orders|reports|support -secret-file <service.secret>` runs a Fetch business API, with independent authenticated receipts, state and reset. Defaults honor `EAT_PORT_OFFSET`; `-listen` and `-control` select explicit loopback addresses. Orders uses `-inventory <http-origin>` and Reports uses `-orders <http-origin>` for authenticated internal calls. With `-tls-cert`, `-tls-key` and `-client-ca` (all three, or none) the API serves TLS and admits only clients presenting a certificate issued by that CA; only then may `-listen` name an address other than loopback. Inventory and Orders then also answer their `/internal/` endpoints, and nothing else, on `127.0.0.1` at the same port, where the other services' calls arrive. The control listener is always loopback. Accounts takes the same TLS flags.
- `cmd/accounts -secret-file <service.secret> -signing-settings <accounts.json>` runs Fetch Accounts. Signing settings contain `kid` and an absolute `private_key_file`. Only Accounts signs application tokens, which last 15 minutes. Account and signing secrets stay in the private demonstration state.
- `cmd/demo` builds, sets up and runs the full local stack with `up`. `up -role fetch -programs <folder>` runs the services, Accounts and shop already built in that folder instead of building them, as the container image does; `prepare` gives a new gateway started from the APIWard image its administrator and baseline; `health` succeeds once every Fetch service on the host answers, the image's health check. `setup` writes `gateway.json`, complete baseline and deny-all policies, `service.secret`, a signing key pair and `accounts.json` into a new identified private directory, then installs the first administrator. `run` starts the five services and the gateway, serves the shop's built files on the website upstream, reports protected admission separately from listening, and stops its own children gracefully. `token` is an optional client of Accounts for a seeded subject; it cannot change the fixed 15-minute lifetime. `reset` restores every service's seed and clears its receipts. `events` prints request events from the gateway's active audit file; retained rotated files are not searched.
- `cmd/measure -samples 30 -account cust-001` collects preliminary paired wallet latency against an isolated running stack, directly and through the gateway. It honors `EAT_PORT_OFFSET`, keeps credentials out of output, checks equivalent successful responses, and emits raw observations and aggregate JSON.
- `internal/services`: the four APIs and Accounts. `internal/ports`: the demonstration addresses.
- `client/`: the shop (React and TypeScript, built with Vite) and its browser tests; see its README. `e2e/`: the browser-test helpers shared with APIWard's Dashboard tests. `openapi/`: an OpenAPI description of each API.

## Requirements

Go 1.26 or newer (`go.mod` selects the Go 1.27.3 toolchain) and Node.js. The demo tool builds the gateway and its Dashboard from an APIWard checkout, by default the folder `apiward` beside this repository:

```
git clone https://github.com/Alex-Zechariah-02/apiward
git clone https://github.com/Alex-Zechariah-02/fetch
cd fetch
```

`-apiward <folder>` names another checkout. The Fetch programs themselves need nothing from APIWard; one test imports APIWard's public `policy` package at the version pinned in `go.mod`, and CI checks APIWard out at that same commit.

## One command

```
go run ./cmd/demo up
```

Each run builds the gateway, services, Accounts and both websites from the current sources. It prints all fourteen fictional demo accounts; their shared public password is `FetchDemo2026!`. The first run asks you to choose a separate password for the Dashboard administrator `root`, then establishes deny-all genesis and confirms the Fetch baseline through the Admin API. Later runs keep the administrator and policy; service business data starts from its deterministic seed on restart. Programs, builds and state are kept in `EAT40005-demo` in the user cache folder (`%LOCALAPPDATA%` on Windows); `-home <dir>` chooses another folder. `-fresh` replaces identified earlier state and creates a fresh version 4 deployment; it never migrates a version 3 policy. Press Ctrl+C to stop everything. `-stdin` also stops when standard input closes, after any password prompts.

If an earlier native setup stopped before any administrator, candidate or policy existed, `up` recognizes that unfinished state, asks for the initial Dashboard password and preserves the complete earlier directory under `state-before-fetch-<id>` in the same home before creating the Fetch setup at `state/`. An earlier deployment with saved authority, mismatched files, a corrupt database or another process holding it is refused before building.

The Dashboard is at `http://127.0.0.1:9440/` and the shop at `http://127.0.0.2:9480/`, through the gateway; `run` serves the shop's files itself on `127.0.0.1:9506`, the website's upstream. Metrics are at `http://127.0.0.1:9450/metrics`. `EAT_PORT_OFFSET` shifts every port; for example, `1000` selects data port 10480, admin port 10440 and metrics port 10450.

At the default offset, Inventory, Orders, Reports, Support and Accounts listen on `127.0.0.1:9501` through `9505`, with protected control listeners on `9601` through `9605`. Orders reserves Inventory stock and Reports reads Orders history through fixed `/internal/` endpoints with `X-Service-Key` from `service.secret`. Those endpoints have no gateway routes. Every service response carries `X-Service`; gateway refusals do not. The controls expose `/state`, `/receipts` and `/reset` with a separate bearer secret. Keep the state directory and all service and control listeners private to the local demonstration.

## Standalone (unprotected)

```
go run ./cmd/demo up -standalone
```

Runs the shop, the four APIs and Accounts with no gateway, to show the application before it is protected. It needs no APIWard checkout. The demo process listens on the shop's address (`http://127.0.0.2:9480/`), serves the shop and forwards each API path to its service. **Nothing is checked:** it copies the `sub` and `roles` claims of any bearer token into the identity headers the services read, without verifying the token, so a token with made-up roles is believed; only identity headers sent by the client are discarded. Never use this mode to protect anything. Each run makes a new folder `standalone` in the demo home with a new signing key; tokens from an earlier run stop working. `-fresh` and `-apiward` are refused with `-standalone`.

## Moving the APIs behind APIWard

Each API has an OpenAPI 3.1 description in `openapi/`: `inventory`, `orders`, `reports`, `support` and `accounts` `.openapi.yaml`. They describe the endpoints, sign-in and request bodies, and carry Fetch's own `x-fetch-roles` and `x-fetch-access` members. APIWard's import passes `x-fetch-*` members through unread and takes no roles or rate limits from a description, so an administrator sets those in the Dashboard.

```
go run ./cmd/demo migrate -out <new-policy-file>
go run ./cmd/demo policy stage -dir <home>/state -file <new-policy-file>
```

`migrate` builds the gateway from the APIWard checkout and runs `gateway policy import-openapi` once per API, onto a base that holds the services' addresses, the roles and the shop's pages, and writes one policy file; it stops if any endpoint is refused. Staging saves it as a draft change in the running gateway; in the Dashboard, give each endpoint its roles and rate limit, put the change on trial and keep it. `-openapi <folder>` reads the descriptions from another folder, such as a copy from the Fetch host; `-fetch <ip>` builds onto a gateway host's base, whose services are on the Fetch host over TLS (see Two hosts), and the file is then staged with `-dir <home>/gateway`. On any other gateway, copy the descriptions there and run `gateway policy import-openapi` directly; it reads only the files it is given.

## Two hosts

Fetch and the gateway can run on separate machines: the Fetch host serves the shop, the four APIs and Accounts on one network address over TLS, admitting only the gateway's client certificate; the gateway host runs APIWard, which reaches them with that certificate and serves the shop over HTTPS. Browsers reach only the gateway.

```
go run ./cmd/demo certs -out <new-folder> -fetch <fetch-ip> -gateway <gateway-name-or-ip>[,...]
go run ./cmd/demo up -role fetch -bind <fetch-ip> -certs <folder>/fetch                (on the Fetch host)
go run ./cmd/demo up -role gateway -fetch <fetch-ip> -certs <folder>/gateway           (on the gateway host)
```

`certs` writes two folders. `fetch` holds a new private CA's certificate, Fetch's server certificate for `<fetch-ip>` and the private key Accounts signs with; `gateway` holds the CA certificate, the gateway's client certificate, its certificate for the shop's names and the Accounts public key, which is how the gateway learns which tokens to trust; for the APIWard container image it also holds the image's settings `apiward.json` and the `deny-all.json` and `baseline.json` policies. The CA's key is never written, so nothing else can be issued from it; the certificates last 30 days. `certs` refuses an existing `-out` folder: for new certificates, run it into a new folder (or delete the old one first), copy both new folders again and start the gateway with `-fresh`, or in containers install again after `docker compose down -v`, which deletes the gateway's database, administrator and policy. Copy each folder to its host only.

On the Fetch host, the APIs and Accounts listen on `<fetch-ip>` ports 9501 to 9505 and the shop on 9506; the control listeners and the calls between services stay on `127.0.0.1`. Every run starts from seed with a new service secret. On the gateway host, the shop and APIs are at `https://<gateway-name>:9480/` on every interface, while the Dashboard (`127.0.0.1:9440`) and metrics (`127.0.0.1:9450`) stay on loopback: reach the Dashboard through an SSH tunnel (`ssh -N -L 9440:127.0.0.1:9440 <user>@<gateway-host>`, then `http://127.0.0.1:9440/`). The first gateway run asks for the administrator password and establishes the baseline, whose services are `https://<fetch-ip>:<port>` with the client certificate; later runs reuse it (`-fresh` starts over). `-tls-cert` and `-tls-key` on the first run serve a public certificate, such as certbot's files, instead of the private one. With the private CA, browsers warn unless its `ca.pem` is trusted. `EAT_PORT_OFFSET` applies on both hosts. `deploy/README.md` describes firewall rules and running both hosts as systemd services on Linux.

## Containers

`Dockerfile` builds an image of the shop's build and the `demo`, `services` and `accounts` programs, in `/opt/fetch`, running as the non-root user 65532 on the distroless static Debian 13 image. It runs `demo up -role fetch -programs /opt/fetch` with the fetch folder of `demo certs` mounted read-only and a temporary `/tmp`, so every start begins from seed; its health check is `demo health`. `compose.yaml` runs it beside the APIWard image, built from the APIWard checkout beside this one (`APIWARD=<folder>` names another), on one Linux host with Docker Engine and its Compose plugin. Both containers use the host's network, so the Dashboard and metrics stay on the host's loopback and no address translation sits in the request path; both run with a read-only root file system, no capabilities and `no-new-privileges`, and pass `EAT_PORT_OFFSET` through. The gateway keeps its database and security log in the named volume `gateway`. The images are built inside Docker, so only `demo certs` needs Go.

First run, in the Fetch checkout:

```
go run ./cmd/demo certs -out $HOME/fetch-certs -fetch 127.0.0.3 -gateway localhost,127.0.0.1
sudo chown -R 65532:65532 $HOME/fetch-certs
export FETCH_IP=127.0.0.3 CERTS=$HOME/fetch-certs
docker compose build
docker compose run --rm gateway install --config /etc/apiward/apiward.json --admin root
docker compose up -d
docker compose run --rm setup
```

1. `certs` can run on any machine with Go; copy the folder to the host. `127.0.0.3` is a loopback address, which keeps Fetch off the network. The folder holds private keys, so it lives outside this checkout, where Git never sees it.
2. The images read the folder as UID and GID 65532, and the gateway uses a key only when nobody else can read it. Afterwards only `sudo` reads the files, so copy `gateway/ca.pem` from it first if a browser or `demo attack -ca` on this machine needs it.
3. `FETCH_IP` must be the `-fetch` address given to `certs` and `CERTS` the folder it wrote; Compose refuses to start without either. `build` builds both images.
4. `install` prints a one-time enrolment secret; keep it private. The administrator must be `root`, the name `setup` signs in with. This also starts Fetch, which the gateway depends on.
5. `up -d` starts the gateway once Fetch is healthy. Until step 6 the gateway shows `starting`, then `unhealthy`: it has no policy yet.
6. `setup` runs `demo prepare` once, reading only `baseline.json` and `deny-all.json` from the gateway folder (the keys stay with the gateway): it asks for the enrolment secret and then a new Dashboard password twice, without showing them, establishes deny-all genesis, confirms the Fetch baseline and prints the demo accounts.

The shop is then at `https://localhost:9480/` (browsers warn unless the folder's `gateway/ca.pem` is trusted), the Dashboard at `http://127.0.0.1:9440/` (sign in as `root`) and the metrics, `/livez` and `/readyz` at `http://127.0.0.1:9450`. From another machine, reach the Dashboard through an SSH tunnel as in Two hosts.

Later:

```
docker compose up -d
docker compose stop
docker compose down
```

The gateway keeps its administrator, policy and security log across restarts and `down`, which keeps the volume; `docker compose down -v` deletes them, and the next start needs `install` and `setup` again. Fetch starts from seed every time, so `docker compose restart fetch` resets its data. Every `docker compose` command needs the same `FETCH_IP` and `CERTS` (and `APIWARD` when set); a `.env` file beside `compose.yaml` can hold them.

Two hosts run the same images. Make the folders with `-out $HOME/fetch-certs -fetch <fetch-ip> -gateway <gateway-name>`, copy its `fetch` folder to `$HOME/fetch-certs/fetch` on the Fetch host and its `gateway` folder to `$HOME/fetch-certs/gateway` on the gateway host, and run `sudo chown -R 65532:65532 $HOME/fetch-certs` on each. With `FETCH_IP=<fetch-ip>` and `CERTS=$HOME/fetch-certs` exported on both hosts, start the Fetch host first with `docker compose up -d fetch`, then on the gateway host:

```
docker compose build
docker compose run --rm --no-deps gateway install --config /etc/apiward/apiward.json --admin root
docker compose up -d --no-deps gateway
docker compose run --rm --no-deps setup
```

The gateway host builds both images, since `setup` runs from the Fetch image, so it needs both checkouts, or the images copied with `docker save` and `docker load`. The shop is then at `https://<gateway-name>:9480/`. The network rules are those of `deploy/README.md`, section 1; its "Containers instead" describes these hosts.

Docker Desktop offers host networking only as an opt-in setting (version 4.34 or later, Settings > Resources > Network, signed in to Docker), at layer 4 and without binding the host's IP addresses, so the documented setup is Linux with Docker Engine; the one-host first run and later commands were tested with Docker Engine 29.1.3 and Compose 2.40.3 on Ubuntu 26.04. Containers on the host's network with a local volume add no network hop, but measurements compare only runs made the same way: never containers against programs in one comparison.

## Demonstration commands

While the stack is running, these commands use its identified `state` directory:

```
go run ./cmd/demo reset -dir <home>/state
go run ./cmd/demo attack -dir <home>/state -scenario flood-search -from 127.0.0.50 -count 65
go run ./cmd/demo attack -dir <home>/state -scenario flood-login -from 127.0.0.51 -count 12
go run ./cmd/demo attack -dir <home>/state -scenario flood-orders -from 127.0.0.52 -count 12
go run ./cmd/demo keys rotate -dir <home>/state
go run ./cmd/demo keys retire -dir <home>/state -kid <old-key-id>
go run ./cmd/demo policy export -dir <home>/state -out <new-policy-file>
go run ./cmd/demo policy stage -dir <home>/state -file <policy-file>
go run ./cmd/demo events -dir <home>/state -last 20
```

`attack -target https://<gateway-name>:9480 -scenario ... [-ca <folder>/gateway/ca.pem]` sends the same traffic to a gateway on another host from this machine's own address, checking the gateway's certificate against the CA file or the system's roots; it needs no `-dir`.

The order flood signs in as Customer 2 (`cust-002`), keeping Customer 1's (`cust-001`) checkout quota separate. It creates real demonstration cash orders until limited; reset the demo afterwards. Different source addresses isolate the public search and login quotas.

Key and policy commands prompt for the `root` Dashboard password and use its session, Origin and CSRF protections. Rotation writes a new pair locally, adds public trust and reloads it before switching Accounts; the old key remains trusted until retirement. The current Accounts key cannot be retired. A failed or unconfirmed reload leaves Accounts signing unchanged and reports the uncertainty. Policy export writes only to a new file. Policy staging validates a complete candidate against the current confirmed revision and does not activate it. No command automatically repeats a write without an answer.

Money uses integer sen, wallets start at 10000 sen and checkout keys replay the first exact result without repeating the charge or reservation. Business state is in memory.

To run the stack by hand, build the programs, put APIWard's Dashboard build in `<web-dir>/admin` and the shop build in `<web-dir>/demo`, then:

```
go build -trimpath -o <out-dir>/services.exe ./cmd/services
go build -trimpath -o <out-dir>/accounts.exe ./cmd/accounts
go build -trimpath -o <out-dir>/demo.exe ./cmd/demo
demo setup -dir <new-dir> -web <web-dir> -gateway <gateway-binary>
demo run -dir <new-dir> -web <web-dir> -gateway <gateway-binary> -services <out-dir>/services.exe -accounts <out-dir>/accounts.exe
```

## Tests

```
go mod verify
gofmt -l .
go vet ./...
go test ./... -count=1
```

The integration tests start all five services and walk the role flows, refusals, policy changes, blocks, keys and resets. They use synthetic identities and temporary state; real Accounts tests create private signing files in temporary directories. No application signing key is shipped in source. The shop's browser tests are described in `client/README.md`.

## Licence

Apache-2.0 (`LICENSE`). Third-party components, the typeface and the photos are listed with their licences in `THIRD_PARTY_NOTICES`.
