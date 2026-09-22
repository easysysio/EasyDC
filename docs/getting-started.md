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
| **LDAP URL** | `ldaps://dc1.example.com` | `ldap://` works, but see below |
| **Bind DN** | `CN=Administrator,CN=Users,DC=example,DC=com` | The account EasyDC acts as |
| **Bind Password** | | Stored in the EasyDC database |
| **Skip TLS Verify** | on for self-signed | Samba's default certificate is self-signed |

!!! warning "Use LDAPS"
    Samba rejects password writes (`unicodePwd`) over plain LDAP, so **password resets and
    new users with a password need an `ldaps://` URL** on port 636. Plain LDAP also sends the
    bind password in the clear.

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
