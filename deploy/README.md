# Two hosts on Linux

How to run Fetch and APIWard on two Linux machines, for example two virtual machines of one cloud provider in one private network. Browsers reach only the gateway. The Fetch host admits only the gateway's client certificate, and its firewall admits only the gateway's address. The commands are those of the README's "Two hosts" section; this page adds the network rules, the installation and systemd.

| Host | Runs | Listens on |
|---|---|---|
| Fetch | `demo up -role fetch`: the shop, Inventory, Orders, Reports, Support, Accounts | `<fetch-ip>` TCP 9501 to 9506 (TLS, gateway client certificate required); `127.0.0.1` for the control listeners (9601 to 9605) and the calls between services |
| Gateway | `demo up -role gateway`: APIWard and its Dashboard | every interface TCP 9480 (HTTPS: the shop and the APIs); `127.0.0.1:9440` (Dashboard), `127.0.0.1:9450` (metrics, `/livez`, `/readyz`) |

`<fetch-ip>` is the Fetch host's private address, which the gateway connects to. Ports move with `EAT_PORT_OFFSET` on both hosts.

## 1. Network rules

Allow only these inbound connections; deny everything else.

| Host | Port | From |
|---|---|---|
| Gateway | TCP 22 (SSH) | your own address |
| Gateway | TCP 9480 | the addresses that open the shop (yours, the room's network) |
| Fetch | TCP 22 (SSH) | your own address |
| Fetch | TCP 9501 to 9506 | the gateway only |

On AWS, put each machine in its own security group. A new security group has no inbound rules, and rules only allow. For the Fetch group, add an inbound rule for TCP 9501-9506 whose source is the gateway's security group: it admits the private addresses of the gateway's instances. A single address is written as `/32`, for example `203.0.113.10/32` for your own address on port 22.

As a second layer on the Fetch host (Ubuntu's `ufw`; replace `<gateway-ip>` with the gateway's private address and `<your-ip>` with yours):

```
sudo ufw default deny incoming
sudo ufw allow proto tcp from <your-ip> to any port 22
sudo ufw allow proto tcp from <gateway-ip> to any port 9501:9506
sudo ufw enable
```

The certificates still refuse every client but the gateway when a rule is missing; the firewall keeps the rest of the network from even connecting.

## 2. Software (both hosts)

Go at the version of `go.mod`'s `toolchain` line and Node.js 24, from their official downloads; for Go:

```
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go<version>.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

Node.js: unpack the `linux-x64` archive from nodejs.org (for example into `/opt/node`) and add its `bin` folder to `PATH`. Check each download against the checksums published beside it.

Clone this repository on both hosts, and APIWard beside it on the gateway host:

```
git clone https://github.com/Alex-Zechariah-02/fetch
git clone https://github.com/Alex-Zechariah-02/apiward      (gateway host only)
```

Use the same commits on both hosts.

## 3. Certificates

On one machine with a checkout:

```
go run ./cmd/demo certs -out $HOME/fetch-certs -fetch <fetch-ip> -gateway <gateway-name>
```

`<gateway-name>` is the name or address browsers use for the gateway (for example its public IP or DNS name; several, comma-separated). The folder holds private keys, so it is made outside the checkout, where Git never sees it. Copy its `fetch` folder to the Fetch host and its `gateway` folder to the gateway host, for example with `scp -r`, and keep the files readable only by the account that runs the demo (`chmod 700` on the folder, `chmod 600` on the files: the gateway refuses a key file others can read). Each host gets only its own folder. Whoever holds `client-key.pem` can call Fetch as the gateway, with any caller identity, so it stays on the gateway host; whoever holds `issuer-key.pem` can sign tokens, so it stays on the Fetch host. When the certificates expire, the gateway refuses Fetch's certificate and answers `502` until new ones are in place. To renew or change an address, run `certs` again and copy both folders.

## 4. First run

The first gateway run asks for the Dashboard administrator's password, so run both hosts once by hand:

```
go run ./cmd/demo up -role fetch -bind <fetch-ip> -certs ~/fetch-certs/fetch -home ~/fetch-demo                (Fetch host)
go run ./cmd/demo up -role gateway -fetch <fetch-ip> -certs ~/fetch-certs/gateway -home ~/apiward-demo         (gateway host)
```

Start the Fetch host first: the gateway's baseline needs it to answer. With a public certificate for the shop, add `-tls-cert <fullchain.pem> -tls-key <privkey.pem>` to the gateway's first run; the files must be readable by the account that runs it, the key by that account only.

Open the shop at `https://<gateway-name>:9480/`. The Dashboard stays on the gateway's loopback; from your machine:

```
ssh -N -L 9440:127.0.0.1:9440 <user>@<gateway-host>
```

then open `http://127.0.0.1:9440/`. On an Ubuntu image on AWS, `<user>` is `ubuntu`.

Stop both with Ctrl+C before installing the services below.

## 5. systemd

Build the demo tool once on each host (`go build -o ~/bin/demo ./cmd/demo` in the Fetch checkout). `up` builds the programs and websites from the checkout on every start, so the service needs Go and Node.js on its `PATH` and the checkout as its working directory. Fetch host, `/etc/systemd/system/fetch.service` (replace the user, paths and address):

```
[Unit]
Description=Fetch (two-host setup)
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
User=ubuntu
WorkingDirectory=/home/ubuntu/fetch
Environment=HOME=/home/ubuntu
Environment=PATH=/usr/local/go/bin:/opt/node/bin:/usr/bin:/bin
ExecStart=/home/ubuntu/bin/demo up -role fetch -bind <fetch-ip> -certs /home/ubuntu/fetch-certs/fetch -home /home/ubuntu/fetch-demo
KillMode=mixed
TimeoutStopSec=30
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Gateway host, `/etc/systemd/system/apiward.service`: the same with `Description=APIWard (two-host setup)` and

```
ExecStart=/home/ubuntu/bin/demo up -role gateway -fetch <fetch-ip> -certs /home/ubuntu/fetch-certs/gateway -home /home/ubuntu/apiward-demo
```

Then on each host:

```
sudo systemctl daemon-reload
sudo systemctl enable --now fetch        (apiward on the gateway host)
journalctl -u fetch -f
```

`KillMode=mixed` sends the stop signal to the demo tool alone, which stops its own children within 12 seconds; anything left is killed when `TimeoutStopSec` runs out. Each process also writes its own log in the demo home (`fetch/` on the Fetch host, `gateway/` on the gateway host).

## Operating

- **Reset Fetch's data:** restart the Fetch service; every start begins from seed.
- **Checks from elsewhere:** `go run ./cmd/demo attack -target https://<gateway-name>:9480 -scenario flood-login -count 12 -ca $HOME/fetch-certs/gateway/ca.pem` from any machine that may open the shop.
- **Health:** on the gateway host, `curl http://127.0.0.1:9450/readyz` answers `ok` only while the gateway accepts requests.
- **Change the Fetch address or certificates:** run `certs` again, copy both folders, and start the gateway with `-fresh` (its first run records the address and the certificate files); this replaces its administrator and policy.

## Containers instead

Both hosts can run the container images of the README's "Containers" section instead of sections 2, 4 and 5. Each host needs Linux with Docker Engine and its Compose plugin (`docker compose`), from the distribution's packages or Docker's official ones (https://docs.docker.com/engine/install/), and a Fetch checkout; the gateway host also needs the APIWard checkout beside it to build the images, or both images copied with `docker save` and `docker load`. Only the machine that runs `demo certs` needs Go. The network rules of section 1 stay the same: both containers use the host's network, so Fetch listens on `<fetch-ip>` and the gateway on every interface at 9480, with the Dashboard and metrics on its loopback.

Make the folders as in section 3: Compose requires `CERTS` to name a folder outside the Fetch checkout, so the private keys never sit in a Git working tree. Copy its `fetch` folder to `$HOME/fetch-certs/fetch` on the Fetch host and its `gateway` folder to `$HOME/fetch-certs/gateway` on the gateway host. The images run as UID and GID 65532, so on each host:

```
sudo chown -R 65532:65532 $HOME/fetch-certs
export FETCH_IP=<fetch-ip> CERTS=$HOME/fetch-certs
```

Fetch host, first:

```
docker compose up -d fetch
```

Gateway host:

```
docker compose build
docker compose run --rm --no-deps gateway install --config /etc/apiward/apiward.json --admin root
docker compose up -d --no-deps gateway
docker compose run --rm --no-deps setup
```

`install` prints a one-time enrolment secret; keep it private. `setup` reads only `baseline.json` and `deny-all.json` from the gateway folder; it asks for the secret and a new Dashboard password, then establishes the baseline. The shop and the SSH tunnel to the Dashboard are as in section 4.

No systemd unit is needed: `restart: unless-stopped` starts the containers again whenever Docker starts, unless they were stopped by hand. `docker compose restart fetch` resets Fetch's data, `docker compose logs -f` follows the logs and `docker compose ps` shows each container's health. `docker compose down` keeps the gateway's volume; `down -v` deletes its database, administrator and policy.
