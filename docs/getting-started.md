# Getting started

## Create the admin account

The first visit to `http://<host>:3000/` redirects to **`/setup`**. Choose a username and
password; the password is stored as a bcrypt hash in the EasyDC database. From then on
the setup page is closed and the UI requires a login.

## Add a domain controller

On the dashboard, click **Add Server** and fill in:

| Field | Example | Notes |
|---|---|---|
| **Name** | `DC1` | Any label; shown on the dashboard |
| **LDAP URL** | `ldaps://dc1.example.com` | Use `ldaps://`: see below |
| **Bind DN** | `CN=Administrator,CN=Users,DC=example,DC=com` | The account EasyDC acts as |
| **Bind Password** | | Stored in the EasyDC database |
| **Skip TLS Verify** | on for self-signed | Samba's default certificate is self-signed |

!!! warning "Use LDAPS"
    By default Samba does not accept a password over plain LDAP, so with an `ldap://` URL
    EasyDC cannot sign in at all. Use `ldaps://` (port 636) and the DC's name rather than its
    IP address, since the certificate is made out to the name. Even where a DC allows
    `ldap://`, it refuses password writes over it, and the bind password crosses the network
    in the clear.

**Skip TLS Verify**: Samba makes its own certificate, which nothing trusts until you
install the domain's CA certificate on the EasyDC machine. Until then, turn this on. The
connection stays encrypted, but EasyDC does not check that it is talking to your DC. Each
server's card on the dashboard shows which it is: *Certificate checked*, *Certificate not
checked*, or *Not encrypted*.

When you save a server, EasyDC signs in to it once and shows the result at the top of the
dashboard. If that fails, the message says why and what to change: a wrong password, a
disabled or locked bind account, a certificate this machine does not trust, a wrong port,
a name not in DNS, or Samba not running on the DC.

The bind account needs read/write access to the parts of the directory you want to manage —
in practice a member of **Domain Admins** for full use.

To change a server later, edit it from the dashboard. Leaving **Bind Password** empty keeps
the stored one.

## Find your way around

Opening a server shows one card per area:

| Card | What it covers |
|---|---|
| **User Management** | Accounts, password resets, unlocks |
| **Group Management** | Security and distribution groups, membership |
| **Computer Management** | Computer accounts |
| **DNS Management** | AD-integrated zones and records |
| **GPO Management** | Group Policy Objects and their OU links |
| **Health Check** | Read-only diagnostics for the domain |
| **OU Management** | The OU tree and moving objects between OUs |

**Settings** in the top bar manages the EasyDC sign-in accounts: change your own
password, and add an account for each person who administers the domain.

The **Audit Log** button in the top bar is global: it lists changes across every server.

Next: [what you can do in each area](managing.md).
