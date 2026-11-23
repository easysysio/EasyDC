# Installation

EasyDC is packaged for the **Debian** and **Red Hat** families on **x86_64** and
**arm64**. Install it from the EasySYS package repository so upgrades arrive through your
package manager, or run it [with Docker](#docker) on any system. Nothing is installed on your domain controllers — EasyDC reaches them
over LDAP/LDAPS.

The binary is **statically linked**, so it depends on no system library and runs on any
Linux distribution of either family — RHEL 8 and Debian 10 included — and the bare binary
runs on others such as Alpine.

## Install from the package repository

=== "Debian / Ubuntu"

    ```bash
    # Add the EasyDC repository (signed)
    curl -fsSL https://repo.easysys.io/easydc/stable/debian/key.gpg \
      | sudo gpg --dearmor -o /usr/share/keyrings/easysys.gpg
    echo "deb [signed-by=/usr/share/keyrings/easysys.gpg] https://repo.easysys.io/easydc/stable/debian ./" \
      | sudo tee /etc/apt/sources.list.d/easydc.list

    sudo apt update
    sudo apt install easydc
    sudo systemctl enable --now easydc
    ```

=== "RHEL / Fedora"

    ```bash
    sudo tee /etc/yum.repos.d/easydc.repo >/dev/null <<'EOF'
    [easydc]
    name=EasyDC
    baseurl=https://repo.easysys.io/easydc/stable/redhat
    enabled=1
    gpgcheck=1
    gpgkey=https://repo.easysys.io/easydc/stable/redhat/key.gpg
    EOF

    sudo dnf install easydc
    sudo systemctl enable --now easydc
    ```

=== "openSUSE / SLES"

    ```bash
    sudo zypper addrepo -fg https://repo.easysys.io/easydc/stable/redhat easydc
    sudo zypper install easydc
    sudo systemctl enable --now easydc
    ```

=== "Manual download"

    For air-gapped hosts, grab the `.deb` or `.rpm` for your architecture from the
    [releases page](https://github.com/easysysio/EasyDC/releases):

    ```bash
    sudo dpkg -i easydc_*_amd64.deb     # or _arm64.deb
    sudo rpm  -i easydc-*.x86_64.rpm    # or .aarch64.rpm
    sudo systemctl enable --now easydc
    ```

    Upgrades then mean downloading the next package by hand — the repository is the
    easier path where the host has network access.

Already using another EasySYS product, such as EasyLog? The key is the same, so
`/usr/share/keyrings/easysys.gpg` is already in place — add only the `easydc` repository
line.

## What the package installs

| | |
|---|---|
| **Binary** | `/usr/bin/easydc` |
| **Service** | `easydc.service`, running as the `easydc` system user |
| **Database** | `/var/lib/easydc/easydc.db`, in a directory only the service user can read |
| **Port** | 3000, over [HTTPS](#https) — set `EASYDC_PORT` in `/etc/default/easydc` (Debian) or `/etc/sysconfig/easydc` (Red Hat) to change it |

The database holds the EasyDC logins, the audit log and the **bind password of every
domain controller you add**, which is why its directory is mode `0700`.

A fresh install does not start the service — `systemctl enable --now easydc` does. An
upgrade restarts the service if it was running, so the new version takes effect. Removing
the package stops and disables the service but **leaves `/var/lib/easydc` and the
`easydc` user in place**: they are your data.

## Upgrading

Upgrades come through the package manager like any other package:

=== "Debian / Ubuntu"

    ```bash
    sudo apt update && sudo apt upgrade
    ```

=== "RHEL / Fedora"

    ```bash
    sudo dnf upgrade easydc
    ```

=== "openSUSE / SLES"

    ```bash
    sudo zypper update easydc
    ```

A running service is restarted onto the new version; a stopped one is left stopped.
`easydc --version` shows which version is installed, and the version is also in the footer
of every page once you are signed in.

To remove EasyDC, `sudo apt remove easydc` or `sudo dnf remove easydc` stops and disables
the service. `/var/lib/easydc` and the `easydc` user are kept — they hold your database —
so delete them yourself if you are removing EasyDC for good.

### Moving from a manual install

If EasyDC already runs as a service you set up by hand — from the old README recipe, or a
binary in `/opt` or anywhere else — installing the package moves it over for you
(from **0.3.1**; with 0.3.0, follow [the steps below](#by-hand)).

It looks for a hand-made unit at `/etc/systemd/system/easydc.service` that runs something
other than `/usr/bin/easydc`. That unit matters because systemd reads `/etc` before the
package's own unit, so left alone it would keep starting the old binary. When it finds one,
the install:

1. stops the old service;
2. copies `easydc.db` from the old unit's working directory into `/var/lib/easydc`, owned
   by the `easydc` user — unless a database is already there;
3. keeps a `--port` from the old command line, in `/etc/default/easydc` or
   `/etc/sysconfig/easydc`;
4. disables the old unit and renames it to `easydc.service.pre-package`;
5. starts the packaged service if the old one was running.

**Nothing is deleted.** The old binary, database and unit stay where they were, so you can
check everything and remove them later — or go back. The install prints each step, and
afterwards

```bash
systemctl cat easydc | head -1
```

should show `/usr/lib/systemd/system/easydc.service`. Log in with your existing account and
your servers should all be there.

The step runs on every install and upgrade and does nothing when there is nothing to move;
run `/usr/share/easydc/migrate-legacy` yourself to repeat it. A unit in
`/etc/systemd/system` that already runs `/usr/bin/easydc` is taken as a deliberate
override and left alone.

#### By hand

On 0.3.0, or to do it yourself, first see what the old service runs and where it keeps its
database — the `WorkingDirectory` line, or `/` if there is none:

```bash
systemctl cat easydc
```

Then, as root, with `/opt/easydc` standing in for that directory:

```bash
systemctl stop easydc && cp -a /opt/easydc /opt/easydc.bak
install -d -o easydc -g easydc -m 700 /var/lib/easydc
cp /opt/easydc/easydc.db* /var/lib/easydc/
chown easydc:easydc /var/lib/easydc/easydc.db* && chmod 600 /var/lib/easydc/easydc.db*
systemctl disable easydc && rm /etc/systemd/system/easydc.service && systemctl daemon-reload
systemctl enable --now easydc
```

If the old `ExecStart` had `--port`, put the same port in `/etc/default/easydc` (Debian) or
`/etc/sysconfig/easydc` (Red Hat) as `EASYDC_PORT=…` before the last line.

## Without a package

On a distribution outside both families — the binary is static, so any will do — or to
try EasyDC out, the bare binary is on the
[releases page](https://github.com/easysysio/EasyDC/releases) too:

=== "x86_64"

    ```bash
    curl -fLo easydc https://github.com/easysysio/EasyDC/releases/latest/download/easydc-linux-x86_64
    chmod +x easydc
    ```

=== "arm64"

    ```bash
    curl -fLo easydc https://github.com/easysysio/EasyDC/releases/latest/download/easydc-linux-arm64
    chmod +x easydc
    ```

Run it in place:

```bash
./easydc
```

It serves [HTTPS](#https) on **port 3000** on all interfaces and creates `easydc.db` in the **current
working directory**. To use a different port, pass `--port` or set `EASYDC_PORT`; the
flag wins:

```bash
./easydc --port 8080
EASYDC_PORT=8080 ./easydc
```

`./easydc --help` lists the options, and `./easydc --version` prints the version. For a permanent install without a package, the
[unit the package ships](https://github.com/easysysio/EasyDC/blob/main/packaging/easydc.service)
is a good starting point.

## Docker

EasyDC is also a container image for **x86_64** and **arm64**,
[`easysysio/easydc` on Docker Hub](https://hub.docker.com/r/easysysio/easydc), published
with each release. It runs anywhere Docker or Podman does. The image is Alpine with the
same static binary as the packages, and runs as its own non-root user.

| Tag | What it is |
|---|---|
| `latest` | The newest release |
| `0.5` | The newest 0.5.x release |
| `0.5.1` | That release only |

=== "docker run"

    ```bash
    docker run -d --name easydc --restart unless-stopped \
      -p 3000:3000 -v easydc-data:/data \
      easysysio/easydc:latest
    ```

=== "Docker Compose"

    Each [GitHub release](https://github.com/easysysio/EasyDC/releases) has a
    `compose.yaml` with the image pinned to that version. Download the latest one and
    start it:

    ```bash
    curl -fsSLO https://github.com/easysysio/EasyDC/releases/latest/download/compose.yaml
    docker compose up -d
    ```

    Or write it yourself (the repository has the
    [same file](https://github.com/easysysio/EasyDC/blob/main/compose.yaml), with
    `latest`):

    ```yaml
    services:
      easydc:
        image: easysysio/easydc:latest
        container_name: easydc
        restart: unless-stopped
        ports:
          - "3000:3000"
        volumes:
          - easydc-data:/data

    volumes:
      easydc-data:
    ```

Then open `https://<host>:3000/` to create the admin account.

- **Your data** is one file, `easydc.db`, in the `/data` volume: the EasyDC accounts,
  the servers with their bind passwords, and the audit log. Back up the volume. To use a
  host folder instead of a named volume, make it owned by the container's user and
  private: `sudo install -d -o 10001 -g 10001 -m 0700 /srv/easydc`, then
  `-v /srv/easydc:/data`.
- **Upgrading** is pulling the new image and recreating the container:
  `docker compose pull && docker compose up -d`, or `docker pull` and `docker run` again
  with the same volume. The database is updated on first start, as with the packages.
  With a release's `compose.yaml`, change the version in `image:` first. Use `:0.5`
  instead of `:latest` to get fixes but choose when to move to 0.6.
- **Another port**: publish a different one, such as `-p 8080:3000`.
- **Finding the DCs**: the container uses the host's DNS. If the DCs' names are only in
  the domain's own DNS, add `--dns <DC address>` (or `dns:` in Compose), so that an
  `ldaps://dc.example.com` URL resolves and matches the DC's certificate.
- **Trusting the DCs' certificates**: Samba makes its own certificate, which the image
  does not trust. Either turn on *Skip TLS verify* for the server, or mount the domain's
  CA certificate and point `SSL_CERT_FILE` at it:
  `-v ./domain-ca.pem:/certs/domain-ca.pem:ro -e SSL_CERT_FILE=/certs/domain-ca.pem`.
- **Building the image yourself**: `docker build -t easydc .` in a checkout of the
  repository.

## HTTPS

EasyDC serves **HTTPS on port 3000**. There is no second port: `http://<host>:3000/`
redirects to `https://<host>:3000/`, so firewalls and Docker port mappings stay as they
are, including when you upgrade from a version before 0.6.

**The browser's warning.** On first start EasyDC makes a self-signed certificate and
renews it itself. Traffic is encrypted, but browsers warn about it because nothing vouches
for it. To be sure it is really EasyDC before you accept, compare the browser's SHA-256
fingerprint with the one in the log (`journalctl -u easydc` or `docker logs easydc`).

**Your own certificate.** In **Settings → HTTPS certificate**, choose **Use my
certificate** and give it the certificate and its private key as PEM files, without a
passphrase. Put the server's certificate first, then any intermediates. It applies to new
connections right away, with no restart. EasyDC warns in Settings as it nears expiry, but
renewing it is up to you. The certificate and key are stored in `easydc.db`, so back that
file up and keep it private.

**Behind a reverse proxy.** [EasyWAF](https://easywaf.easysys.io), Nginx and Caddy all work.
Choose one:

- Keep HTTPS on, and have the proxy send `X-Forwarded-Proto` (Caddy does by default; in
  Nginx add `proxy_set_header X-Forwarded-Proto $scheme;`). EasyDC then answers it over
  plain HTTP and marks its session cookie `Secure`.
- Or turn EasyDC's HTTPS off with `EASYDC_TLS=off`, in `/etc/default/easydc`,
  `/etc/sysconfig/easydc`, or the container's environment. Firewall port 3000 to the proxy.

!!! warning "A proxy without that header"
    It gets the redirect to HTTPS instead of the page. Add the header or set
    `EASYDC_TLS=off` when you upgrade to 0.6.

!!! note "Two separate TLS links"
    This protects the browser → EasyDC connection. The EasyDC → domain controller
    connection is protected by using an `ldaps://` URL when you add the server.

**Health checks.** `/healthz` answers `ok` over plain HTTP too, without a redirect.

## First run

Open `https://<host>:3000/`. On a fresh install you are sent to **`/setup`** to create the
admin account; after that every page requires a login.

Next: [create the admin account and add your first domain controller](getting-started.md).
