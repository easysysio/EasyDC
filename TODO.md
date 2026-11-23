# TODO

**0.6.0** is built and waiting for release: its items are the sections down to "From
samba-tool". After it, the aim is to run Samba AD with no Windows machine, and to hear about
problems before users do. What earlier releases brought is in `CHANGELOG.md`.

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
- **Launch it.** Post the release on the Samba mailing list, r/sysadmin and r/selfhosted, with
  screenshots and the one-line Docker install, and let real users shape what comes next.

## 0.8.0: SYSVOL drift detection, then GPO settings

So that a domain needs no Windows machine with GPMC, and an edit cannot quietly reach only
some DCs.

### First: SYSVOL drift detection

Samba does not replicate SYSVOL, so a change made on one DC stays there until the admin's own
sync copies it. EasyDC should show when the DCs disagree. This part is read-only.

- **Compare every DC over SMB**, with the PDC emulator as the reference:
  - each GPO's folder is there;
  - the version in `GPT.INI` matches the directory object;
  - the same files, with the same contents (SHA-256, because sync tools change timestamps);
  - the permissions are what `samba-tool ntacl sysvolcheck` expects;
  - the `scripts` folder, which holds logon scripts;
  - folders in SYSVOL with no GPO in the directory.
- **Give each GPO a clear state on each DC:** in sync, missing, older, newer, different
  contents, wrong permissions, or unknown. A DC that cannot be reached or read is **unknown**,
  never "in sync".
- **Show it where admins look:** a status column on the Group Policy page, a per-DC view of
  each GPO, and a new SYSVOL check on the Health page.
- **Warn after every change.** After a GPO is created, edited or deleted, name the DCs that
  do not have it yet.
- **Protect edits.** Refuse to edit a GPO when another DC holds a newer copy, because the edit
  would split it in two. A DC that is behind or down only gets a warning.
- **Mark sudo rules as urgent.** A rule removed on one DC can still grant access through
  another, so drift in a GPO with sudo rules is shown first.
- **Keep it light.** Pages compare versions and file lists. The full comparison of contents
  runs on request, with a limit on file size and a timeout for each DC.
- **No repair yet.** EasyDC says what differs and where, and the admin's sync fixes it. Add a
  sync only if people ask, because a bad sync can damage policies on every DC.
- **Test on LAB:** a GPO on one DC only, a changed file, an older version, wrong permissions,
  a leftover folder, and a DC that is down.

### Then: edit GPO settings

- **Start with about ten popular settings**, such as logon scripts, mapped drives and common
  security options.
- **Sudo rules for Linux computers.** View, add and remove the rules `samba-gpupdate` applies
  (`samba-tool gpo manage sudoers`). Ask for a password by default, and warn before a
  `NOPASSWD` rule. Test on a real Linux client joined to the domain.
- **Write them as GPMC does:** the policy files, the version in both `GPT.INI` and the
  directory object, and the client extension lists, or clients silently ignore the change.
- **Test every setting on real Windows clients** before it ships.

## 0.8.x: SSH public keys

With the sudo rules from 0.8.0, one place controls who can log in to Linux servers and what
they can do there. Samba's schema has no attribute for SSH keys, and `samba-tool` has no
command for them.

- **Schema, once.** Add the standard `sshPublicKey` attribute and `ldapPublicKey` class.
  Schema additions cannot be deleted, so test on LAB first. EasyDC detects whether the schema
  is ready and, if not, shows the commands to run on the DC, like the functional level guide.
  Do not use `altSecurityIdentities` instead: Kerberos uses it to map certificates to accounts.
- **Keys on each user's page.** Add and remove keys, show fingerprints, reject weak or
  malformed keys, and record every change in the audit log. Never handle private keys.
- **Limit who can write keys to admins.** Anyone who can change this attribute can log in as
  that user on every server.
- **A report** of users with keys, flagging disabled accounts that still have them.
- **Document the Linux side:** SSSD, and `AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys`
  in `sshd`, how long a removed key can stay cached, and that a key login gets no Kerberos
  ticket, so network shares may need `kinit`.
- **Test on a real Linux client:** a key works, a removed key stops working, and disabled and
  locked accounts are refused, because key login skips the password.

## 0.9.0: monitoring and alerts

- **Scheduled health checks**, using the checks EasyDC already has.
- **Email and webhook alerts** for failed replication, expiring certificates, clock skew and
  lost FSMO roles.
- **Alert on SYSVOL drift**, by running the 0.8.0 comparison on a schedule.

## 1.0: trust and recovery

- **Restore deleted objects.** First check how well Samba supports bringing a deleted object
  back over LDAP.
- **Tested upgrades** from older versions.
- **A security review.**
- **Kerberos for SMB.** GPO creation depends on NTLM today, and more domains turn it off.

## Maybe later

- **One search box** across users, groups and computers.
- **SSO and a public API**, if users ask for them.

## Not planned

They need DCE/RPC: forcing a sync now (`samba-tool drs replicate`), creating and deleting
DNS zones through Samba's DNS service (which would remove the wait for a samba restart
after deleting a zone), and trusts.
