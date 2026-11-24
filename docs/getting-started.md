# Getting started

## Create the admin account

The first visit to `https://<host>:3000/` redirects to **`/setup`**. EasyDC makes its own
certificate, so the browser warns once; [your own certificate](install.md#https) removes the
warning. Choose a username and
password; the password is stored as a bcrypt hash in the EasyDC database. From then on
the setup page is closed and the UI requires a login.

## Add a domain controller

On the Servers page, click **Add Server** and fill in:

| Field | Example | Notes |
|---|---|---|
| **Name** | `DC1` | Any label; shown on the Servers page |
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
server's card on the Servers page shows which it is: *Certificate checked*, *Certificate not
checked*, or *Not encrypted*.

When you save a server, EasyDC signs in to it once and shows the result at the top of the
Servers page. If that fails, the message says why and what to change: a wrong password, a
disabled or locked bind account, a certificate this machine does not trust, a wrong port,
a name not in DNS, or Samba not running on the DC.

The bind account needs read/write access to the parts of the directory you want to manage —
in practice a member of **Domain Admins** for full use.

To change a server later, edit it from the Servers page. Leaving **Bind Password** empty keeps
the stored one.

## Find your way around

Opening a server shows its **Overview**: how many users, groups, computers and DCs it has,
what **needs attention** (from the health check and the accounts), and whether replication
works. The sidebar on the left keeps the current server in view; the box at its top
switches to another server and stays on the same kind of page.

| Sidebar | What it covers |
|---|---|
| **Users** | Accounts, password resets and settings, unlocks, CSV export and import |
| **Groups** | Security and distribution groups, membership |
| **Computers** | Computer accounts, by OU |
| **OUs** | The OU tree, and moving objects between OUs |
| **SPNs** | Service principal names on users and computers |
| **Group Policy** | Group Policy Objects and their OU links |
| **Password policy** | The domain's password and lockout policy, and policies for groups and users |
| **Delegation** | Letting a group do a job in an OU, such as resetting passwords |
| **DNS** | AD-integrated zones and records |
| **Domain controllers** | Each DC's site and FSMO roles; moving roles and removing a dead DC |
| **Replication** | Which DC each DC receives from, and whether it worked |
| **Sites** | Sites, subnets and site links |
| **Health** | Read-only diagnostics for the domain |
| **Reports** | Inactive accounts, password expiry, privileged groups and more, with CSV export |

- **Search** at the top, or **Ctrl-K** (**⌘K** on a Mac), finds users, groups, computers and
  pages by name. Use the arrow keys and Enter to open one.
- A click on a user, group, computer, OU, GPO or DNS record opens its **details beside the
  list**, where you can change it. A click on another row switches to that one.
- The **moon** at the top switches between light and dark mode. Until you choose, EasyDC
  follows your system's setting.
- On a phone, the sidebar is behind the **menu** button at the top left.

At the bottom of the sidebar, **All servers** lists every server, and the **Audit log** lists
changes across all of them. **Settings** manages who can sign in to EasyDC: add an account
for each person who administers the domain, with what each may change. An account can be
local, with its own password, or a domain account that signs in with its domain password.
Everyone can view every page. **Your name**, at the top right, has your own password and
two-factor sign-in.

Next: [what you can do in each area](managing.md).
