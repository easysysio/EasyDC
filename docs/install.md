# Installation

EasyDC ships as a **single binary** for Linux **x86_64** and **arm64**. Templates are
compiled in, so the binary is the whole install; the only file it writes at runtime is
its SQLite database. Nothing is installed on your domain controllers — EasyDC reaches
them over LDAP/LDAPS.

## Download

Grab the binary for your architecture from the
[releases page](https://github.com/easysysio/EasyDC/releases):

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

To try it out, run it in place:

```bash
./easydc
```

EasyDC listens on **port 3000** on all interfaces and creates `easydc.db` in the
**current working directory**.

To use a different port, pass `--port` or set `EASYDC_PORT`; the flag wins:

```bash
./easydc --port 8080
EASYDC_PORT=8080 ./easydc
```

`./easydc --help` lists the options.

## Run as a systemd service

For a permanent install, give EasyDC a dedicated user and a working directory of its own:

```bash
sudo cp easydc /usr/local/bin/easydc
sudo useradd -r -s /bin/false easydc
sudo mkdir -p /var/lib/easydc
sudo chown easydc:easydc /var/lib/easydc
```

```ini title="/etc/systemd/system/easydc.service"
[Unit]
Description=EasyDC - Samba AD Management GUI
After=network.target

[Service]
Type=simple
User=easydc
WorkingDirectory=/var/lib/easydc
ExecStart=/usr/local/bin/easydc --port 3000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now easydc
sudo systemctl status easydc
```

The database then lives at `/var/lib/easydc/easydc.db`. It holds the EasyDC logins, the
audit log and the **bind passwords** of the servers you add, so keep it readable by the
`easydc` user only.

## Put TLS in front of it

EasyDC serves **plain HTTP** on port 3000. Anywhere beyond a trusted management network,
publish it through a TLS reverse proxy — [EasyWAF](https://easywaf.easysys.io), Nginx or
Caddy all work — and firewall port 3000 to the proxy.

!!! note "Two separate TLS links"
    The proxy protects the browser → EasyDC connection. The EasyDC → domain controller
    connection is protected by using an `ldaps://` URL when you add the server.

## First run

Open `http://<host>:3000/`. On a fresh install you are sent to **`/setup`** to create the
admin account; after that every page requires a login.

Next: [create the admin account and add your first domain controller](getting-started.md).
