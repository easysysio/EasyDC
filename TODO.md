# TODO

**0.6.0** is built and waiting for release: its items are the sections down to "From
samba-tool". **0.7.0** is a full redesign. What earlier releases brought is in `CHANGELOG.md`.

## Securing EasyDC itself

EasyDC keeps the bind passwords of accounts that can change the whole domain.

- ~~**HTTPS built in.**~~ Done: on port 3000, with plain HTTP redirected, a self-signed
  certificate or your own from Settings, and `EASYDC_TLS=off` for reverse proxies.
- ~~**Two-factor sign-in.**~~ Done: an authenticator app for local accounts, with recovery
  codes, an admin reset, `--reset-2fa` on the host, and a switch to require it for local
  admins. Domain accounts keep signing in with their domain password.

## Group Policy

- ~~**Create a GPO's SYSVOL folder.**~~ Done: over SMB to the PDC emulator with the `smb2`
  library, undone if any step fails. Deleting a GPO removes the folder too. Samba does not
  replicate SYSVOL, so other DCs still need the admin's own sync.

## Reports

~~**Reports.**~~ Done: inactive accounts, expiring and never-expiring passwords, locked,
disabled or expired accounts, privileged group members including nested ones, and empty
groups, each with CSV export.

## From samba-tool, over LDAP

Same rule as in 0.5.0: Samba is GPLv3 and EasyDC is MIT. Read its source
(`python/samba/netcmd/`) and Microsoft's MS-ADTS to learn what is written, but do not copy
its code.

- ~~**SPNs** on users and computers: view, add and remove (`samba-tool spn`).~~
- ~~**Raise the functional level** of the domain and forest.~~ Done as a guide: Samba allows a
  raise only from a shell on a DC, so EasyDC shows the exact commands each level still needs.

## 0.7.0: a full redesign

EasyDC has grown page by page and looks messy. Give it a clean, modern and consistent design.

- **Agree on the look first.** Mock up the Dashboard, the Users page and one detail page, and
  choose a direction before any page changes.
- **Rethink the navigation.** Moving between a server's areas should not mean going back to a
  grid of cards. Consider a sidebar, with the current server always visible.
- **One design system.** Colors, type, spacing, buttons, badges, tables, forms and dialogs
  defined in one place, replacing the 41 inline styles and per-page variations.
- **Redo all 33 page templates** on it, with the same page header, tables, filters, row
  actions, and empty, loading and error states everywhere.
- **Split the largest pages.** Users (937 lines) and Settings (600) do too much in one template.
- **Dark mode**, following the system setting, with a switch to override it.
- **Works at every size**, from a phone to a wide screen, and by keyboard and screen reader.
- **Nothing is lost.** Every feature and permission check stays, and all assets stay bundled,
  so EasyDC keeps working on a network with no internet access.

## Maybe later

- **One search box** across users, groups and computers.
- **Restore deleted objects.** First check how well Samba supports bringing a deleted
  object back over LDAP.

## Not planned

They need DCE/RPC: forcing a sync now (`samba-tool drs replicate`), creating and deleting
DNS zones through Samba's DNS service (which would remove the wait for a samba restart
after deleting a zone), and trusts.
