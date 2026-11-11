# The demo tool

`demo up` in detail and the commands that act on a running stack. Back to the [README](../README.md).

## One command

```
go run ./cmd/demo up
```

Each run builds the gateway, services, Accounts and both websites from the current sources. It prints all fourteen fictional demo accounts; their shared public password is `FetchDemo2026!`. The first run asks you to choose a separate password for the Dashboard administrator `root`, then establishes deny-all genesis and confirms the Fetch baseline through the Admin API. Later runs keep the administrator and policy; service business data starts from its deterministic seed on restart. Programs, builds and state are kept in `EAT40005-demo` in the user cache folder (`%LOCALAPPDATA%` on Windows); `-home <dir>` chooses another folder. `-fresh` replaces identified earlier state and creates a fresh version 4 deployment; it never migrates a version 3 policy. Press Ctrl+C to stop everything. `-stdin` also stops when standard input closes, after any password prompts.

If an earlier native setup stopped before any administrator, candidate or policy existed, `up` recognizes that unfinished state, asks for the initial Dashboard password and preserves the complete earlier directory under `state-before-fetch-<id>` in the same home before creating the Fetch setup at `state/`. An earlier deployment with saved authority, mismatched files, a corrupt database or another process holding it is refused before building.

The Dashboard is at `http://127.0.0.1:9440/` and the shop at `http://127.0.0.2:9480/`, through the gateway; `run` serves the shop's files itself on `127.0.0.1:9506`, the website's upstream. Metrics are at `http://127.0.0.1:9450/metrics`. `EAT_PORT_OFFSET` shifts every port; for example, `1000` selects data port 10480, admin port 10440 and metrics port 10450.

At the default offset, Inventory, Orders, Reports, Support and Accounts listen on `127.0.0.1:9501` through `9505`, with protected control listeners on `9601` through `9605`. Orders reserves Inventory stock and Reports reads Orders history through fixed `/internal/` endpoints with `X-Service-Key` from `service.secret`. Those endpoints have no gateway routes. Every service response carries `X-Service`; gateway refusals do not. The controls expose `/state`, `/receipts` and `/reset` with a separate bearer secret. Keep the state directory and all service and control listeners private to the local demonstration.

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
