# Fetch

A fictional food and grocery delivery application for demonstrating and testing [APIWard](https://github.com/Alex-Zechariah-02/apiward), a security policy gateway for REST APIs.

- A React shop
- Four business APIs: Inventory, Orders, Reports, Support
- Fetch Accounts: signs in users and issues their tokens
- All data is synthetic

## Requirements

- Go 1.26+ (`go.mod` selects the 1.27.4 toolchain)
- Node.js 24
- An APIWard checkout beside this one (not needed for `-standalone` or `-local`)

```
git clone https://github.com/Alex-Zechariah-02/apiward
git clone https://github.com/Alex-Zechariah-02/fetch
cd fetch
```

## Quick start

```
go run ./cmd/demo up
```

- Builds and starts the gateway, its Dashboard, the services and the shop.
- The first run asks for a password for the Dashboard administrator `root`.
- Prints the fourteen demo accounts. Their password is `FetchDemo2026!`.
- Ctrl+C stops everything.

| Open | Address |
|---|---|
| Shop, through the gateway | `http://127.0.0.2:9480/` |
| Dashboard (sign in as `root`) | `http://127.0.0.1:9440/` |
| Metrics | `http://127.0.0.1:9450/metrics` |

| Option | Effect |
|---|---|
| `-fresh` | Start over with a new administrator and policy |
| `-home <dir>` | Where programs and state are kept |
| `-apiward <dir>` | Use another APIWard checkout |
| `EAT_PORT_OFFSET=<n>` | Shift every port by `n` |

## Ways to run

`demo` below means `go run ./cmd/demo`.

| Mode | Command | Protection |
|---|---|---|
| Behind APIWard | `demo up` | The gateway checks, limits and logs every request |
| Standalone | `demo up -standalone` | None. For showing the unprotected application only |
| Built-in | `demo up -local` | Each API checks requests itself, no gateway |
| Two hosts | `demo certs`, then `demo up -role fetch` and `demo up -role gateway` | Gateway and Fetch on separate machines, mutual TLS |
| Containers | `docker compose up` | Both as container images |

- Standalone, built-in, and importing the APIs into APIWard from OpenAPI: [docs/modes.md](docs/modes.md)
- Two hosts and containers: [docs/hosts.md](docs/hosts.md)
- Server setup: [deploy/README.md](deploy/README.md)

## Demo commands

Run while the stack is up. `<state>` is `<home>/state`.

| Command | Effect |
|---|---|
| `demo reset -dir <state>` | Restore seed data |
| `demo attack -dir <state> -scenario flood-login -count 12` | Send a flood (`flood-login`, `flood-search`, `flood-orders`) |
| `demo events -dir <state> -last 20` | Print the latest security log records |
| `demo keys rotate -dir <state>` | Switch Accounts to a new signing key |
| `demo policy export -dir <state> -out <file>` | Save the policy in force |
| `demo policy stage -dir <state> -file <file>` | Save a policy as a draft change |

Details: [docs/demo.md](docs/demo.md).

## Project layout

| Path | Contents |
|---|---|
| `client/` | The shop: React, TypeScript, Vite ([client/README.md](client/README.md)) |
| `cmd/services` | The four business APIs |
| `cmd/accounts` | Fetch Accounts |
| `cmd/demo` | The demo tool |
| `cmd/measure` | Preliminary latency measurement |
| `internal/services` | API and Accounts code, operation tables |
| `internal/guard` | Built-in protection |
| `openapi/` | OpenAPI 3.1 description of each API |
| `e2e/` | Browser-test helpers |
| `deploy/` | Running on Linux servers |
| `load/` | Load-test scripts |

Program flags: [docs/programs.md](docs/programs.md).

## Tests

```
go mod verify
gofmt -l .
go vet ./...
go test ./... -count=1
```

Shop and browser tests: [client/README.md](client/README.md).

## Licence

Apache-2.0 (`LICENSE`). Third-party components, typeface and photos: `THIRD_PARTY_NOTICES`.
