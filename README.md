# Fetch

A fictional food and grocery delivery application, built to demonstrate and test [APIWard](https://github.com/Alex-Zechariah-02/apiward), a security policy gateway for REST APIs.

Fetch is a React shop, four business APIs (Inventory, Orders, Reports, Support) and Fetch Accounts, which signs in users and issues their tokens. Every account, merchant, item and order is synthetic.

- [Quick start](#quick-start)
- [Ways to run](#ways-to-run)
- [Demo commands](#demo-commands)
- [Project layout](#project-layout)
- [Development](#development)

## Requirements

- Go 1.26 or newer (`go.mod` selects the Go 1.27.4 toolchain)
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

This builds and starts the gateway, its Dashboard, the five services and the shop. The first run asks for a password for the Dashboard administrator `root`. Press Ctrl+C to stop.

| | |
|---|---|
| Shop, through the gateway | `http://127.0.0.2:9480/` |
| Dashboard (sign in as `root`) | `http://127.0.0.1:9440/` |
| Metrics | `http://127.0.0.1:9450/metrics` |

`up` prints the fourteen demo accounts (customers, merchants, riders, support and operations staff). Their shared password is `FetchDemo2026!`.

Useful flags: `-fresh` starts over with a new administrator and policy, `-home <dir>` chooses where programs and state are kept, `-apiward <dir>` names another APIWard checkout. `EAT_PORT_OFFSET` shifts every port. Details: [reference/demo.md](reference/demo.md).

## Ways to run

| Mode | Command | What it shows |
|---|---|---|
| Behind APIWard | `demo up` | Every page and API call is checked, rate-limited and logged by the gateway. The APIs answer only requests the gateway signed. |
| Standalone | `demo up -standalone` | The application with no protection at all. Never use it to protect anything. |
| Built-in protection | `demo up -local` | No gateway: each API checks tokens, roles, rates and bodies itself. |
| Two hosts | `demo certs`, then `demo up -role fetch` and `demo up -role gateway` | Fetch and the gateway on separate machines, over mutual TLS. |
| Containers | `docker compose up` | Both as hardened container images on one or two Linux hosts. |

`demo` is short for `go run ./cmd/demo`. Standalone, built-in protection and moving the APIs behind APIWard with OpenAPI: [reference/modes.md](reference/modes.md). Two hosts and containers: [reference/hosts.md](reference/hosts.md); server setup: [deploy/README.md](deploy/README.md).

## Demo commands

While the stack runs (`<state>` is `<home>/state`):

```
go run ./cmd/demo reset -dir <state>                                  # back to seed data
go run ./cmd/demo attack -dir <state> -scenario flood-login -count 12 # also flood-search, flood-orders
go run ./cmd/demo events -dir <state> -last 20                        # latest security log records
go run ./cmd/demo keys rotate -dir <state>                            # new Accounts signing key
go run ./cmd/demo policy export -dir <state> -out <new-file>
go run ./cmd/demo policy stage -dir <state> -file <policy-file>
```

All commands and their rules: [reference/demo.md](reference/demo.md).

## Project layout

| Path | Contents |
|---|---|
| `client/` | The shop: React and TypeScript, built with Vite ([client/README.md](client/README.md)) |
| `cmd/services` | The four business APIs |
| `cmd/accounts` | Fetch Accounts |
| `cmd/demo` | The demo tool: build, set up, run, attack, reset |
| `cmd/measure` | Preliminary latency measurement |
| `internal/services` | The APIs, Accounts and each API's operation table |
| `internal/guard` | Built-in protection |
| `openapi/` | An OpenAPI 3.1 description of each API |
| `e2e/` | Browser-test helpers, shared with APIWard's Dashboard tests |
| `deploy/` | Running on Linux servers |
| `load/` | Load-test scripts |

Program flags: [reference/programs.md](reference/programs.md).

## Development

Work on the shop as described in [client/README.md](client/README.md). Go checks:

```
go mod verify
gofmt -l .
go vet ./...
go test ./... -count=1
```

The integration tests start all five services and walk the role flows, refusals, policy changes, blocks, keys and resets, with synthetic identities and temporary state. No signing key is shipped in source.

## Licence

Apache-2.0 (`LICENSE`). Third-party components, the typeface and the photos are listed with their licences in `THIRD_PARTY_NOTICES`.
