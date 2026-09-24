# Installation

EasyDC is packaged for the **Debian** and **Red Hat** families on **x86_64** and
**arm64**. Install it from the EasySYS package repository so upgrades arrive through your
package manager. Nothing is installed on your domain controllers — EasyDC reaches them
over LDAP/LDAPS.

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

The keyring is shared with the other EasySYS products, which are signed with the same key.

## What the package installs

| | |
|---|---|
| **Binary** | `/usr/bin/easydc` |
| **Service** | `easydc.service`, running as the `easydc` system user |
| **Database** | `/var/lib/easydc/easydc.db`, in a directory only the service user can read |
| **Port** | 3000 — set `EASYDC_PORT` in `/etc/default/easydc` (Debian) or `/etc/sysconfig/easydc` (Red Hat) to change it |

The database holds the EasyDC logins, the audit log and the **bind password of every
domain controller you add**, which is why its directory is mode `0700`.

A fresh install does not start the service — `systemctl enable --now easydc` does. An
upgrade restarts the service if it was running, so the new version takes effect. Removing
the package stops and disables the service but **leaves `/var/lib/easydc` and the
`easydc` user in place**: they are your data.

### Moving from a manual install

Earlier instructions installed EasyDC by hand, with the same `easydc` user and the same
`/var/lib/easydc` directory the package uses, so your database carries over as-is. Remove
the two pieces the package replaces before installing it:

```bash
sudo systemctl disable --now easydc
sudo rm /etc/systemd/system/easydc.service /usr/local/bin/easydc
sudo systemctl daemon-reload
```

The first matters most: a unit in `/etc/systemd/system` takes precedence over the one the
package installs, so leaving it would keep starting the old binary.

## Without a package

On a distribution outside both families, or to try EasyDC out, the bare binary is on the
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

It listens on **port 3000** on all interfaces and creates `easydc.db` in the **current
working directory**. To use a different port, pass `--port` or set `EASYDC_PORT`; the
flag wins:

```bash
./easydc --port 8080
EASYDC_PORT=8080 ./easydc
```

`./easydc --help` lists the options. For a permanent install without a package, the
[unit the package ships](https://github.com/easysysio/EasyDC/blob/main/packaging/easydc.service)
is a good starting point.

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
