# TODO

Everything below is planned for **0.6.0**, except the last section. What 0.5.0 brought is
in `CHANGELOG.md`.

## Securing EasyDC itself

EasyDC keeps the bind passwords of accounts that can change the whole domain.

- ~~**HTTPS built in.**~~ Done: on port 3000, with plain HTTP redirected, a self-signed
  certificate or your own from Settings, and `EASYDC_TLS=off` for reverse proxies.
- ~~**Two-factor sign-in.**~~ Done: an authenticator app for local accounts, with recovery
  codes, an admin reset, `--reset-2fa` on the host, and a switch to require it for local
  admins. Domain accounts keep signing in with their domain password.

## Group Policy

- **Create a GPO's SYSVOL folder**, as `samba-tool gpo create` does, so a new GPO is complete
  without opening it in GPMC. Written over SMB to `\\<dc>\sysvol`. First look at the Rust
  SMB libraries: if none is good enough, this moves to a later release.

## Reports

Read-only, over LDAP, each with CSV export. For the questions an admin asks every week:

- Accounts that have not signed in for a chosen number of days (`lastLogonTimestamp`).
- Passwords that expire soon, and passwords set never to expire.
- Accounts that are locked out, disabled or expired.
- Members of the privileged groups: Domain Admins, Enterprise Admins, Schema Admins,
  Administrators and the other built-in operator groups, including nested members.
- Empty groups.

## From samba-tool, over LDAP

Same rule as in 0.5.0: Samba is GPLv3 and EasyDC is MIT. Read its source
(`python/samba/netcmd/`) and Microsoft's MS-ADTS to learn what is written, but do not copy
its code.

- **SPNs** on users and computers: view, add and remove (`samba-tool spn`).
- **Raise the functional level** of the domain and forest (`samba-tool domain level raise`).
  Admins only.

## Maybe later

- **One search box** across users, groups and computers.
- **Restore deleted objects.** First check how well Samba supports bringing a deleted
  object back over LDAP.

## Not planned

They need DCE/RPC: forcing a sync now (`samba-tool drs replicate`), creating and deleting
DNS zones through Samba's DNS service (which would remove the wait for a samba restart
after deleting a zone), and trusts.
