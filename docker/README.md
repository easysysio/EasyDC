# EasyDC

**Manage Samba Active Directory from the browser.**

EasyDC is a web GUI for Samba AD domain controllers: users, groups, computers, OUs, DNS
records, Group Policy links, password policies, sites, FSMO roles, replication and a
domain health check. It talks to the DCs over LDAPS and needs no agent on them.

* [Documentation](https://easydc.easysys.io/)
* [Source code](https://github.com/easysysio/EasyDC)

---

## Quick start

```bash
docker run -d --name easydc --restart unless-stopped \
  -p 3000:3000 \
  -v easydc-data:/data \
  easysysio/easydc:latest
```

Then open **https://localhost:3000/**. EasyDC makes its own certificate, so the browser
warns once. The first visit creates the admin account. After
signing in, click **Add Server** and give it a DC's `ldaps://` URL and a bind account.

---

## docker compose

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

Each [GitHub release](https://github.com/easysysio/EasyDC/releases) has a `compose.yaml`
pinned to that version:

```bash
curl -fsSLO https://github.com/easysysio/EasyDC/releases/latest/download/compose.yaml
docker compose up -d
```

---

## Data

Everything is in one SQLite file, `/data/easydc.db`: the EasyDC accounts, the servers
with their bind passwords, and the audit log.

**Mount `/data`, or the data goes with the container.** Back up the volume. To use a
host folder, make it owned by the container's user (uid 10001) and private:

```bash
sudo install -d -o 10001 -g 10001 -m 0700 /srv/easydc
docker run ... -v /srv/easydc:/data easysysio/easydc:latest
```

---

## Upgrading

```bash
docker compose pull && docker compose up -d
```

or `docker pull easysysio/easydc:latest` and run the container again with the same
volume. The database is updated on first start.

---

## Settings

| What | How |
|---|---|
| Port | EasyDC listens on 3000. Publish another host port: `-p 8080:3000` |
| DC names | If the DCs are only in the domain's DNS, add `--dns <DC address>` (`dns:` in Compose) |
| LDAPS certificate | Samba makes its own. Turn on *Skip TLS verify* for the server, or mount the domain's CA: `-v ./domain-ca.pem:/certs/domain-ca.pem:ro -e SSL_CERT_FILE=/certs/domain-ca.pem` |

EasyDC serves HTTPS on port 3000 and redirects plain HTTP to it. To remove the browser's
warning, add your own certificate in **Settings**; it is kept in `/data`. Behind a reverse
proxy that handles HTTPS, have it send `X-Forwarded-Proto`, or set `-e EASYDC_TLS=off`.

---

## Tags

* `latest`: the newest release
* `X.Y`: the newest release of a minor version, e.g. `0.6`
* `X.Y.Z`: one release, e.g. `0.6.0`

Multi-arch: `linux/amd64` and `linux/arm64`. The image is Alpine with a static binary,
and runs as a non-root user.

---

MIT licensed.
