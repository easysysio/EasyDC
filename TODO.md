# TODO

The aim is to **replace Windows RSAT for about 90% of daily work**, so a domain needs no
Windows admin machine, and to hear about problems before users do. Rare, risky jobs stay with
`samba-tool`. What earlier releases brought is in `CHANGELOG.md`.

Samba is GPLv3 and EasyDC is MIT. Read its source (`python/samba/netcmd/`) and Microsoft's
MS-ADTS to learn what is written, but do not copy its code.

## 0.7.x: after the redesign

- **Launch it.** Post the release on the Samba mailing list, r/sysadmin and r/selfhosted, with
  the screenshots and the one-line Docker install, and let real users shape what comes next.
- **Split the largest templates.** Users (992 lines) and Settings (592) still do too much in one
  file.
- **The last inline styles.** 24 are left; move them into the stylesheet.

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

## 0.9.x: attribute editor

The most common remaining reason to open ADSI Edit.

- **View first.** Every attribute of any object, searchable, with SIDs, GUIDs, dates and flags
  shown in readable form.
- **Then edit, for admins only.** Read the schema to refuse system-only and computed
  attributes, handle multi-valued ones, and show the old and new value before saving.
- **Never show or write secrets**, such as `unicodePwd` and `supplementalCredentials`.
- **Extra warning on attributes that grant access**, such as `userAccountControl`, SPNs and
  delegation. Security descriptors stay read-only here.
- **Record every change** in the audit log, with the old and new value.

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
