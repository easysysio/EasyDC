# Reference

## Architecture

```mermaid
graph LR
    A["Administrators · any browser"] -->|"HTTP :3000"| B["EasyDC (Rust / Axum)"]
    B -->|"LDAP / LDAPS"| C[("Samba AD DC")]
    B -->|"LDAP / LDAPS"| D[("Samba AD DC")]
    B --> E[("SQLite: logins · servers · audit log")]
```

EasyDC is a web application and an LDAP client in one binary. Each request opens an LDAP
connection to the chosen domain controller, binds as that server's bind account, and reads
or writes the directory directly. Nothing runs on the domain controllers themselves.

EasyDC waits up to **10 seconds** to connect to a DC and up to **30 seconds** for each
answer. A DC that does not answer in time gets a message on the page instead of a page that
never finishes loading. This happens when the DC is down, or busy with a long change such as
deleting an OU with thousands of objects: Samba finishes that before it makes any other
change. A change EasyDC sent may then still be made once the DC is free, so check again in a
few minutes; the audit log records it as failed, with the reason.

## Requirements

| Category | Supported |
|---|---|
| **Directory** | Samba Active Directory domain controller, reachable over LDAP (389) or LDAPS (636) |
| **Bind account** | Read/write access to the partitions you manage; Domain Admins for full use |
| **EasyDC host** | Linux x86_64 or arm64 — `.deb` and `.rpm` packages, a Docker image, or the bare binary |
| **Browser** | Any current browser |

## Files and ports

| | |
|---|---|
| **Web UI** | HTTP on `0.0.0.0:3000`, or `--port` / `EASYDC_PORT` |
| **Database** | `/var/lib/easydc/easydc.db` when installed from a package; `/data/easydc.db` in the Docker image; `easydc.db` in the working directory otherwise |
| **Outbound** | LDAP / LDAPS to each domain controller you add |

## Security notes

- **Bind passwords** for the servers you add are stored in the EasyDC database. Restrict
  the file to the service user.
- **Admin passwords** are stored as bcrypt hashes. Sessions use an `HttpOnly`,
  `SameSite=Strict` cookie, marked `Secure` when the proxy reports HTTPS.
- **Sessions end** after 8 hours without activity, and 24 hours after sign-in however
  active. Changing a password, or removing an administrator, drops that account's other
  sessions.
- The web UI is **plain HTTP**; publish it through a TLS reverse proxy (see
  [Installation](install.md#put-tls-in-front-of-it)).
- **Password writes** require LDAPS; Samba refuses them over plain LDAP.

## Technology

| Component | Library |
|---|---|
| Web framework | [Axum](https://github.com/tokio-rs/axum) |
| Async runtime | [Tokio](https://tokio.rs/) |
| Database | SQLite via [sqlx](https://github.com/launchbadge/sqlx) |
| Templates | [Tera](https://keats.github.io/tera/), compiled into the binary |
| LDAP client | [ldap3](https://github.com/inejge/ldap3) |
| Password hashing | [bcrypt](https://crates.io/crates/bcrypt) |
| UI | Bootstrap 5 + Bootstrap Icons |
