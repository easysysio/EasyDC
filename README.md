# EasyDC

A web-based management GUI for Samba Active Directory Domain Controllers.
Manage users, groups, computers, DNS records, and Group Policy Objects remotely through your browser — no CLI required.

📖 **Documentation: [easydc.easysys.io](https://easydc.easysys.io)**

---

## Features

- **Multi-server dashboard** — add and manage multiple Samba DC servers from one place
- **Users** — create, edit, enable/disable and delete users; reset passwords, unlock, password settings, groups, CSV export and import
- **Groups** — create security/distribution groups, manage memberships
- **Computers** — browse by OU, move, enable/disable and remove computer accounts
- **DNS** — browse zones, add and delete A, AAAA, CNAME, MX, TXT, NS, PTR records (AD-integrated DNS via LDAP)
- **Group Policy** — create GPOs, link/unlink them to OUs
- **OUs** — the OU tree, moving objects, and delegating tasks such as password resets to a group
- **Password policy** — the domain policy, and fine-grained policies for groups and users
- **Domain controllers** — FSMO roles and moving them, removing a dead DC, and replication status
- **Sites and subnets** — sites, subnets and site links
- **EasyDC accounts** — View or Edit per area for each account, local or signing in with a domain password; every change in an audit log
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
- Linux x86_64 or ARM64 — `.deb` and `.rpm` packages, a Docker image, or the bare binary

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

Or with Docker, on any system:

```bash
docker run -d --name easydc --restart unless-stopped \
  -p 3000:3000 -v easydc-data:/data ghcr.io/easysysio/easydc:latest
```

The [installation guide](https://easydc.easysys.io/install/) covers RHEL / Fedora,
openSUSE, Docker, air-gapped hosts, moving from a manual install, and running the bare binary.

The web interface is then at `http://<server-ip>:3000`, where the first visit creates the
admin account. The database is `/var/lib/easydc/easydc.db`.

## Adding a Server

After logging in, click **Add Server** on the dashboard and fill in:

| Field | Example |
|-------|---------|
| Name | My DC |
| LDAP URL | `ldaps://dc.domain.local` (Samba refuses passwords over `ldap://`) |
| Bind DN | `CN=Administrator,CN=Users,DC=domain,DC=local` |
| Bind Password | your password |
| Skip TLS Verify | enable for self-signed certificates |

On saving, EasyDC signs in to the server once and shows whether that worked, and why not.

## Notes

- **Use LDAPS** (port 636). A default Samba DC refuses a password over plain LDAP, so EasyDC cannot sign in over `ldap://`; and where a DC allows it, it still rejects password changes.
- **DNS** manages records stored in the AD DNS partition (`CN=MicrosoftDNS,DC=DomainDnsZones`). Internal zones (`_msdcs`, `RootDNSServers`) are hidden automatically.
- **GPO** manages LDAP metadata (name, status, OU links). Editing actual policy settings (registry values, scripts, etc.) requires direct access to SYSVOL on the DC.
- **Health check** runs entirely over LDAP and changes nothing. Checks that need shell access on the DC — `samba-tool dbcheck`, SYSVOL replication and ACLs, `net ads testjoin`, service status — are out of its reach. The Replication page shows each DC's partners, last success and errors.
- The SQLite database (`easydc.db`) is created automatically on first run in the working directory.

## License

MIT — see [LICENSE](LICENSE).
