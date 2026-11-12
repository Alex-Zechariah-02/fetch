# Two hosts and containers

Server setup, network rules and systemd: [deploy/README.md](../deploy/README.md). Back to the [README](../README.md).

## Two hosts

Fetch and the gateway can run on separate machines: the Fetch host serves the shop, the four APIs and Accounts on one network address over TLS, admitting only the gateway's client certificate; the gateway host runs APIWard, which reaches them with that certificate and serves the shop over HTTPS. Browsers reach only the gateway.

```
go run ./cmd/demo certs -out <new-folder> -fetch <fetch-ip> -gateway <gateway-name-or-ip>[,...]
go run ./cmd/demo up -role fetch -bind <fetch-ip> -certs <folder>/fetch                (on the Fetch host)
go run ./cmd/demo up -role gateway -fetch <fetch-ip> -certs <folder>/gateway           (on the gateway host)
```

### Certificates

- `certs` writes two folders.
- `fetch` holds a new private CA's certificate, Fetch's server certificate for `<fetch-ip>` and the private key Accounts signs with; `gateway` holds the CA certificate, the gateway's client certificate, its certificate for the shop's names, the Accounts public key, which is how the gateway learns which tokens to trust, and the private key the gateway signs its identity assertion with (`assertion-key.pem`; its public half is `assertion-keys.json` in `fetch`); for the APIWard container image it also holds the image's settings `apiward.json` and the `deny-all.json` and `baseline.json` policies.
- The CA's key is never written, so nothing else can be issued from it; the certificates last 30 days.
- `certs` refuses an existing `-out` folder: for new certificates, run it into a new folder (or delete the old one first), copy both new folders again and start the gateway with `-fresh`, or in containers install again after `docker compose down -v`, which deletes the gateway's database, administrator and policy.
- Copy each folder to its host only.

### Running

- On the Fetch host, the APIs and Accounts listen on `<fetch-ip>` ports 9501 to 9505 and the shop on 9506; the control listeners and the calls between services stay on `127.0.0.1`.
- Every run starts from seed with a new service secret.
- On the gateway host, the shop and APIs are at `https://<gateway-name>:9480/` on every interface, while the Dashboard (`127.0.0.1:9440`) and metrics (`127.0.0.1:9450`) stay on loopback: reach the Dashboard through an SSH tunnel (`ssh -N -L 9440:127.0.0.1:9440 <user>@<gateway-host>`, then `http://127.0.0.1:9440/`).
- The first gateway run asks for the administrator password and establishes the baseline, whose services are `https://<fetch-ip>:<port>` with the client certificate; later runs reuse it (`-fresh` starts over).
- `-tls-cert` and `-tls-key` on the first run serve a public certificate, such as certbot's files, instead of the private one.
- With the private CA, browsers warn unless its `ca.pem` is trusted.
- `EAT_PORT_OFFSET` applies on both hosts.
- `deploy/README.md` describes firewall rules and running both hosts as systemd services on Linux.

## Containers

### Images

- `Dockerfile` builds an image of the shop's build and the `demo`, `services` and `accounts` programs, in `/opt/fetch`, running as the non-root user 65531 on the distroless static Debian 13 image (the APIWard image runs as 65532, so on one host neither user can read the other's files).
- It runs `demo up -role fetch -programs /opt/fetch` with the fetch folder of `demo certs` mounted read-only and a temporary `/tmp`, so every start begins from seed; its health check is `demo health`.
- `compose.yaml` runs it beside the APIWard image, built from the APIWard checkout beside this one (`APIWARD=<folder>` names another), on one Linux host with Docker Engine and its Compose plugin.
- Both containers use the host's network, so the Dashboard and metrics stay on the host's loopback and no address translation sits in the request path; both run with a read-only root file system, no capabilities and `no-new-privileges`, and pass `EAT_PORT_OFFSET` through.
- The gateway keeps its database and security log in the named volume `gateway`.
- The images are built inside Docker, and `demo certs` also runs from the Fetch image, so a host with only Docker needs no Go (see First run on one host).

### First run on one host

First run, in the Fetch checkout:

```
go run ./cmd/demo certs -out $HOME/fetch-certs -fetch 127.0.0.3 -gateway localhost,127.0.0.1
sudo chown -R 65531:65531 $HOME/fetch-certs/fetch
sudo chown -R 65532:65532 $HOME/fetch-certs/gateway
export FETCH_IP=127.0.0.3 CERTS=$HOME/fetch-certs
docker compose build
docker compose run --rm gateway install --config /etc/apiward/apiward.json --admin root
docker compose up -d
docker compose run --rm setup
```

1. `certs` can run on any machine with Go; copy the folder to the host. Without Go, build the images first (`FETCH_IP` and `CERTS` exported, `docker compose build`) and run it from the Fetch image as yourself: `docker run --rm --read-only --cap-drop ALL -u "$(id -u):$(id -g)" -v "$HOME:/out" fetch:dev certs -out /out/fetch-certs -fetch 127.0.0.3 -gateway localhost,127.0.0.1`, then continue with the two `chown` lines. `127.0.0.3` is a loopback address, which keeps Fetch off the network. The folder holds private keys, so it lives outside this checkout, where Git never sees it.
2. The Fetch image reads its folder as UID and GID 65531 and the APIWard image its own as 65532, and the gateway uses a key only when nobody else can read it. Afterwards only `sudo` reads the files, so copy `gateway/ca.pem` from it first if a browser or `demo attack -ca` on this machine needs it.
3. `FETCH_IP` must be the `-fetch` address given to `certs` and `CERTS` the folder it wrote; Compose refuses to start without either. `build` builds both images.
4. `install` prints a one-time enrolment secret; keep it private. The administrator must be `root`, the name `setup` signs in with. This also starts Fetch, which the gateway depends on.
5. `up -d` starts the gateway once Fetch is healthy. Until step 6 the gateway shows `starting`, then `unhealthy`: it has no policy yet.
6. `setup` runs `demo prepare` once, reading only `baseline.json` and `deny-all.json` from the gateway folder (the keys stay with the gateway): it asks for the enrolment secret and then a new Dashboard password twice, without showing them, establishes deny-all genesis, confirms the Fetch baseline and prints the demo accounts.

- The shop is then at `https://localhost:9480/` (browsers warn unless the folder's `gateway/ca.pem` is trusted), the Dashboard at `http://127.0.0.1:9440/` (sign in as `root`) and the metrics, `/livez` and `/readyz` at `http://127.0.0.1:9450`.
- From another machine, reach the Dashboard through an SSH tunnel as in Two hosts.
- `../deploy/README.md`, "One host", gives the network rules for running this setup on a server.

### Later runs

Start, stop and remove:

```
docker compose up -d
docker compose stop
docker compose down
```

- The gateway keeps its administrator, policy and security log across restarts and `down`, which keeps the volume; `docker compose down -v` deletes them, and the next start needs `install` and `setup` again.
- Fetch starts from seed every time, so `docker compose restart fetch` resets its data.
- Every `docker compose` command needs the same `FETCH_IP` and `CERTS` (and `APIWARD` when set); a `.env` file beside `compose.yaml` can hold them.

### Containers on two hosts

- Two hosts run the same images.
- Make the folders with `-out $HOME/fetch-certs -fetch <fetch-ip> -gateway <gateway-name>`, copy its `fetch` folder to `$HOME/fetch-certs/fetch` on the Fetch host and its `gateway` folder to `$HOME/fetch-certs/gateway` on the gateway host, and run `sudo chown -R 65531:65531 $HOME/fetch-certs/fetch` on the Fetch host and `sudo chown -R 65532:65532 $HOME/fetch-certs/gateway` on the gateway host.
- With `FETCH_IP=<fetch-ip>` and `CERTS=$HOME/fetch-certs` exported on both hosts, start the Fetch host first with `docker compose up -d fetch`, then on the gateway host:

```
docker compose build
docker compose run --rm --no-deps gateway install --config /etc/apiward/apiward.json --admin root
docker compose up -d --no-deps gateway
docker compose run --rm --no-deps setup
```

- The gateway host builds both images, since `setup` runs from the Fetch image, so it needs both checkouts, or the images copied with `docker save` and `docker load`.
- The shop is then at `https://<gateway-name>:9480/`.
- The network rules are those of `../deploy/README.md`, section 1; its "Containers instead" describes these hosts.

### Docker Desktop

Docker Desktop offers host networking only as an opt-in setting (version 4.34 or later, Settings > Resources > Network, signed in to Docker), at layer 4 and without binding the host's IP addresses, so the documented setup is Linux with Docker Engine; the one-host first run and later commands were tested with Docker Engine 29.1.3 and Compose 2.40.3 on Ubuntu 26.04. Containers on the host's network with a local volume add no network hop, but measurements compare only runs made the same way: never containers against programs in one comparison.
