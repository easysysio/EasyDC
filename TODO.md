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

- **Local**: an account stored in EasyDC's own database, as today.
- **From the domain**: sign in with a domain username and password, checked against the
  DC. The role could come from membership in a domain group (for example
  `EasyDC Admins`, `EasyDC Editors`, `EasyDC Viewers`), so access is managed in AD.

## Next features

- Computers page: browse by OU, move computers, and bulk enable, disable or move.
- A user's groups in the Edit dialog: see them, add and remove.
- Password and logon settings per user: password never expires, must change at next
  logon, cannot change password; when the password was last set and when it expires.
- CSV export and import of users.
- Sites and subnets page.

## Checks and housekeeping

- Large domains: user and group lists are read in one LDAP request without paging. Check
  whether Samba caps the number of results, and page the searches if it does.
- Remove the `RUSTSEC-2026-0459` ignore in `.cargo/audit.toml` once sqlx allows the fixed
  SQLite (libsqlite3-sys 0.39 or later).
