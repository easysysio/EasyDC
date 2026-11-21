# TODO

Everything below is planned for **0.5.0**.

## Permissions for EasyDC accounts

When adding an EasyDC account, an admin sets each area to **View** or **Edit**:

| Area | Edit covers |
|---|---|
| Users | add, edit, delete, enable or disable, reset password, unlock, move to another OU |
| Groups | add, edit, delete, members (also from the Users page and a user's Edit dialog) |
| Computers | enable or disable, delete, move to another OU |
| DNS records | add, edit, delete |
| DNS zones | create, delete |
| GPOs | create, edit, delete, link to OUs |
| OUs | create, rename, delete |
| Password policies | the domain policy and per-group policies |
| Sites and subnets | add, edit, delete (once that page exists) |

- **Edit all** and **View all** buttons set every area at once; single areas can then be changed.
- **Admin** is a separate tick box. It ticks and locks every area, and also covers what only
  admins do: EasyDC accounts, server connections, Settings and the health check's fixes.
  Admin is stored on its own, so areas added later reach admins without editing them, and an
  account with every area on Edit is still not an admin.
- An action needs Edit on what it changes: adding a user to a group needs Groups, moving a
  user needs Users, linking a GPO needs GPOs.
- Everyone can view every page, including replication, the health check and the audit log.
  There is no hidden level.
- In a View area the buttons are greyed out, with a note on who can change that.
- Every action is checked on the server. A refused one gets a clear message on the page and
  a line in the audit log.
- Stored as one row per account and area, so a new area needs no database change.
- On upgrade, existing EasyDC accounts become admins, so nothing stops working.

## Two kinds of EasyDC accounts

An admin adds both kinds in EasyDC and sets their permissions. No groups in AD.

- **Local**: username and password stored in EasyDC's own database, as today.
- **From the domain**: added by domain username, with permissions, like a local account. There
  is no password in EasyDC: signing in checks the password against the DC. A domain
  account that is disabled, expired or locked in AD cannot sign in to EasyDC either.

Keep at least one local admin, so EasyDC can still be reached when the DC is down.

Decided:

- EasyDC makes every change in AD with the server's bind account, after checking the
  person's permissions. The audit log records who did it. People need no rights in AD.
- Permissions apply to every server EasyDC manages, not one server at a time.

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
