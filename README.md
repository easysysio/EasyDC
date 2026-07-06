# EasyDC

A web-based management GUI for Samba Active Directory Domain Controllers.
Manage users, groups, computers, DNS records, and Group Policy Objects remotely through your browser — no CLI required.

---

## Features

- **Multi-server dashboard** — add and manage multiple Samba DC servers from one place
- **User management** — create, edit, enable/disable, and delete AD users
- **Group management** — create security/distribution groups, manage memberships
- **Computer management** — view, enable/disable, and remove computer accounts
- **DNS management** — browse zones, add and delete A, AAAA, CNAME, MX, TXT, NS, PTR records (AD-integrated DNS via LDAP)
- **GPO management** — create and configure Group Policy Objects, link/unlink to OUs
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
- Linux x86_64 or ARM64 (pre-built binaries provided)

## Installation

Download the latest binary from the [Releases](https://github.com/easysysio/EasyDC/releases) page for your architecture:

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `easydc-linux-x86_64` |
| Linux ARM64 | `easydc-linux-arm64` |

```bash
chmod +x easydc-linux-x86_64
./easydc-linux-x86_64
```

The server starts on `http://localhost:3000`.

On first run, navigate to `http://localhost:3000/setup` to create the admin account. You will be redirected automatically if no account exists yet.

## Running as a systemd Service

To have EasyDC start automatically on boot, create a systemd unit file.

1. Copy the binary to a system path:

```bash
sudo cp easydc-linux-x86_64 /usr/local/bin/easydc
sudo chmod +x /usr/local/bin/easydc
```

2. Create a dedicated user and working directory:

```bash
sudo useradd -r -s /bin/false easydc
sudo mkdir -p /var/lib/easydc
sudo chown easydc:easydc /var/lib/easydc
```

3. Create the service file:

```bash
sudo nano /etc/systemd/system/easydc.service
```

Paste the following:

```ini
[Unit]
Description=EasyDC - Samba AD Management GUI
After=network.target

[Service]
Type=simple
User=easydc
WorkingDirectory=/var/lib/easydc
ExecStart=/usr/local/bin/easydc
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

4. Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable easydc
sudo systemctl start easydc
```

5. Check it is running:

```bash
sudo systemctl status easydc
```

The web interface will be available at `http://<server-ip>:3000`.

> The SQLite database is stored in `/var/lib/easydc/easydc.db`.

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
- The SQLite database (`easydc.db`) is created automatically on first run in the working directory.

## License

MIT — see [LICENSE](LICENSE).
