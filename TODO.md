# TODO

Everything below is planned for **0.5.0**, except the last section.

## ~~Permissions for EasyDC accounts~~ — done

Per-area View or Edit and a separate Admin, as described in `docs/managing.md`. When the
Sites and subnets page lands, add it as an area (`src/access.rs`).

## ~~Two kinds of EasyDC accounts~~ — done

Local accounts and domain accounts that sign in with their domain password, as described
in `docs/managing.md`. At least one local admin always remains.

## Next features

- Computers page: browse by OU, move computers, and bulk enable, disable or move.
- A user's groups in the Edit dialog: see them, add and remove.
- Password and logon settings per user: password never expires, must change at next
  logon, cannot change password; when the password was last set and when it expires.
- CSV export and import of users.
- Sites and subnets page.

## From samba-tool, over LDAP

What these `samba-tool` commands do, written in EasyDC. Samba is GPLv3 and EasyDC is MIT:
read its source (`python/samba/netcmd/`) to learn which objects and attributes it
writes, and Microsoft's MS-ADTS for the rules, but do not copy its code. Admins only.

- **Move FSMO roles** between DCs (`samba-tool fsmo transfer`): write the role's
  `become…Master` operation to the target DC's rootDSE. Seizing a role from a dead DC
  needs the DC's own files, so it stays in samba-tool.
- **Remove a dead DC** (`samba-tool domain demote --remove-other-dead-server`): delete its
  NTDS Settings and server objects, its computer account and its DNS records. Refuse while
  it still answers, or while it holds an FSMO role.
- **Delegate control of an OU** (`samba-tool dsacl`): show who has rights on an OU, and give
  a group a common task there, such as resetting passwords or managing users. Edits the
  OU's `nTSecurityDescriptor`.

## Checks and housekeeping

- Remove the `RUSTSEC-2026-0459` ignore in `.cargo/audit.toml` once sqlx allows the fixed
  SQLite (libsqlite3-sys 0.39 or later).

## After 0.5.0

- **Create a GPO's SYSVOL folder**, as `samba-tool gpo create` does, so a new GPO is complete
  without opening it in GPMC. Written over SMB to `\\<dc>\sysvol`: first look at the Rust
  SMB libraries.
- **SPNs** on users and computers (`samba-tool spn`), and **raising the functional level**
  (`samba-tool domain level raise`). Both are LDAP.
- Not planned, because they need DCE/RPC: forcing a sync now (`samba-tool drs replicate`),
  creating and deleting DNS zones through Samba's DNS service (which would remove the wait
  for a samba restart after deleting a zone), and trusts.
