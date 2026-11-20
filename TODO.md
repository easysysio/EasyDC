# TODO

Everything below is planned for **0.5.0**.

## Roles for EasyDC accounts

Three roles:

- **Viewer**: sees everything, changes nothing.
- **Editor**: adds, edits and deletes users, groups, computers and DNS records. Cannot
  touch OUs or GPOs, and cannot add EasyDC accounts.
- **Admin**: everything, including EasyDC accounts, password policies (domain and per
  group), the health check's fixes, and creating or deleting DNS zones.

| Area | Viewer | Editor | Admin |
|---|:-:|:-:|:-:|
| See every page (including replication, the health check and the audit log) | ✅ | ✅ | ✅ |
| Users: add, edit, delete, enable or disable, reset password, unlock, move | — | ✅ | ✅ |
| Groups: add, edit, delete, members | — | ✅ | ✅ |
| Computers: enable or disable, delete, move | — | ✅ | ✅ |
| DNS records: add, edit, delete | — | ✅ | ✅ |
| DNS zones: create, delete | — | — | ✅ |
| OUs: create, rename, delete, move objects | — | — | ✅ |
| GPOs: create, edit, delete, link | — | — | ✅ |
| Password policies (domain-wide and per group) | — | — | ✅ |
| Health check fixes | — | — | ✅ |
| EasyDC accounts: add and remove, assign roles | — | — | ✅ |

Every refused action needs a clear message on the page and a line in the audit log.

## Two kinds of EasyDC accounts

An admin adds both kinds in EasyDC and gives each a role. No groups in AD.

- **Local**: username and password stored in EasyDC's own database, as today.
- **From the domain**: added by domain username, with a role, like a local account. There
  is no password in EasyDC: signing in checks the password against the DC. A domain
  account that is disabled, expired or locked in AD cannot sign in to EasyDC either.

Keep at least one local admin, so EasyDC can still be reached when the DC is down.

Decided:

- EasyDC makes every change in AD with the server's bind account, after checking the
  person's role. The audit log records who did it. People need no rights in AD.
- A role applies to every server EasyDC manages, not one server at a time.

## Next features

- Computers page: browse by OU, move computers, and bulk enable, disable or move.
- A user's groups in the Edit dialog: see them, add and remove.
- Password and logon settings per user: password never expires, must change at next
  logon, cannot change password; when the password was last set and when it expires.
- CSV export and import of users.
- Sites and subnets page.

## Checks and housekeeping

- Remove the `RUSTSEC-2026-0459` ignore in `.cargo/audit.toml` once sqlx allows the fixed
  SQLite (libsqlite3-sys 0.39 or later).
