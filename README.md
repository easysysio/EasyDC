# EasyDC

A web-based management GUI for Samba Active Directory Domain Controllers.
Manage users, groups, computers, DNS records, and Group Policy Objects remotely through your browser — no CLI required.

📖 **Documentation: [easydc.easysys.io](https://easydc.easysys.io)**

---

## Features

- **Multi-server dashboard** — add and manage multiple Samba DC servers from one place
- **User management** — create, edit, enable/disable, and delete AD users
- **Group management** — create security/distribution groups, manage memberships
- **Computer management** — view, enable/disable, and remove computer accounts
- **DNS management** — browse zones, add and delete A, AAAA, CNAME, MX, TXT, NS, PTR records (AD-integrated DNS via LDAP)
- **GPO management** — create and configure Group Policy Objects, link/unlink to OUs
- **Domain health check** — diagnose clock skew, FSMO holders, replication, the DNS service records clients need, LDAPS certificate expiry, and security posture; read-only, over LDAP
- **First-run setup** — guided setup wizard on fresh install; no config files needed

## Tech Stack

| Component | Library |
|-----------|---------|
| Web framework | [Axum](https://github.com/tokio-rs/axum) 0.7 |
| Async runtime | [Tokio](https://tokio.rs/) |
| Database | SQLite via [sqlx](https://github.com/launchbadge/sqlx) |
| Templates | [Tera](https://keats.github.io/tera/) (server-side HTML) |
| LDAP client | [ldap3](https://github.com/inejge/ldap3) |
| Password hashing | [bcrypt](https://crates.io/crates/bcrypt) |
| UI | Bootstrap 5 + Bootstrap Icons |

## Requirements

- A running Samba AD Domain Controller accessible over LDAP/LDAPS
- The bind account needs read/write access to the relevant AD partitions
- Linux x86_64 or ARM64 — `.deb` and `.rpm` packages, or the bare binary

## Installation

EasyDC is packaged for the Debian and Red Hat families on x86_64 and arm64. On
Debian / Ubuntu:

```bash
curl -fsSL https://repo.easysys.io/easydc/stable/debian/key.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/easysys.gpg
echo "deb [signed-by=/usr/share/keyrings/easysys.gpg] https://repo.easysys.io/easydc/stable/debian ./" \
  | sudo tee /etc/apt/sources.list.d/easydc.list
sudo apt update && sudo apt install easydc
sudo systemctl enable --now easydc
```

The [installation guide](https://easydc.easysys.io/install/) covers RHEL / Fedora,
openSUSE, air-gapped hosts, moving from a manual install, and running the bare binary.

The web interface is then at `http://<server-ip>:3000`, where the first visit creates the
admin account. The database is `/var/lib/easydc/easydc.db`.

## Adding a Server

After logging in, click **Add Server** on the dashboard and fill in:

| Field | Example |
|-------|---------|
| Name | My DC |
| LDAP URL | `ldap://192.168.1.10` or `ldaps://dc.domain.local` |
| Bind DN | `CN=Administrator,CN=Users,DC=domain,DC=local` |
| Bind Password | your password |
| Skip TLS Verify | enable for self-signed certificates |

## Notes

- **Password changes** require LDAPS (port 636). Plain LDAP connections will reject `unicodePwd` modifications.
- **DNS** manages records stored in the AD DNS partition (`CN=MicrosoftDNS,DC=DomainDnsZones`). Internal zones (`_msdcs`, `RootDNSServers`) are hidden automatically.
- **GPO** manages LDAP metadata (name, status, OU links). Editing actual policy settings (registry values, scripts, etc.) requires direct access to SYSVOL on the DC.
- **Health check** runs entirely over LDAP and changes nothing. Checks that need shell access on the DC — `samba-tool dbcheck`, SYSVOL replication and ACLs, `net ads testjoin`, service status — are out of its reach. Replication reporting currently covers partner *presence* only; use `samba-tool drs showrepl` for last-success times.
- The SQLite database (`easydc.db`) is created automatically on first run in the working directory.

## License

MIT — see [LICENSE](LICENSE).
