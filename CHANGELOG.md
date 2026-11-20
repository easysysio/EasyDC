# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed
- A group's members page is half the size for large groups.

### Fixed
- A DC that stopped answering left the page loading forever. EasyDC now waits up to 10 seconds to connect and 30 seconds for each answer, then says the DC did not answer and that a change may still be made once it is free.
- The Users page came out blank when the DC could not be reached, instead of saying why.
- A failed change on the Computers or GPO pages was only recorded in the audit log; the page now shows the reason.
- Adding many users to a group at once slowed down as the group grew: 2,000 users took nearly 3 minutes, and now take about 15 seconds.

## [0.4.4] - 2026-11-20

### Added
- Every list (users, groups, members, computers, DNS zones and records, GPOs, OUs, audit log) shows a page at a time, with 25, 50, 100 or 250 rows per page. The search still covers the whole list, and after an action you are back on the same page.
- Users: after ticking a whole page, **Select all** picks every user that matches the search and filter.

### Changed
- The Users page is much lighter for large domains: 2,000 users went from 25 MB to 4.4 MB, and pages are sent compressed (about 110 KB).
- Computers, groups, group members, GPOs, GPO links and OUs use one delete dialog per page instead of one per row, and Groups one Edit dialog.

## [0.4.3] - 2026-11-20

### Added
- Users: select several users to enable, disable, move to an OU, or add to a group at once.
- Users: Move, in each user's new ⋯ menu, to move them to another OU or container.
- Groups: browse by OU or container, as on the Users page, and create a group in the OU you are looking at.

### Changed
- EasyDC refuses to disable, delete or move the account it signs in to the DC with, since that would lock it out.

### Fixed
- The Users page no longer runs wider than the window since the OU tree was added. Less-used actions moved to a ⋯ menu, the email shows under the display name, and the Users and Groups pages use the full window width.
- Creating, renaming, deleting or moving on the OUs page reported nothing when it failed. The reason is shown now.
- Move Object on the OUs page failed for names with a comma, and for a computer given without its `$`, as the form suggests.

## [0.4.2] - 2026-11-20

### Added
- Users: browse by OU or container, with or without the OUs below, and create a user in the OU you are looking at.
- Users: filter by status (enabled, disabled, locked, expired), and search by name, description or email.
- Users: Description, in the Add and Edit dialogs and as a column in the list.
- A search box on every list: groups and their members, computers, DNS zones and records, GPOs and OUs. Inside a DNS zone you can also show a single record type.

### Fixed
- The OU list put an OU whose name contains a comma at the wrong depth.

## [0.4.1] - 2026-11-18

### Security
- Dropped `chrono` and `chrono-tz`, which are unmaintained (RUSTSEC-2026-0543, -0555, -0559). They came with template features EasyDC does not use.

## [0.4.0] - 2026-11-16

### Added
- Replication page: for each DC, where each partition comes from, the last successful sync, and errors in words. The health check now uses it on every DC.
- Password policies for groups and users (PSOs): create, edit, apply, and check which one governs a user. Needs domain level 2008 or higher.
- Groups: change scope and type, and nest groups, following Windows' rules. The members page shows each member's kind and the groups this group belongs to.
- Users: expiry date, job title, department, office, phone, mobile and manager.

### Fixed
- Names with a comma or another special character, such as `Doe, John`, failed or were stored wrongly for users, groups, OUs and DNS records.
- Failed user and group actions only appeared in the audit log. They show on the page now.
- A password refused by the policy was reported as "requires LDAPS".
- Creating a user with a refused password left a disabled account behind.
- Saving a group with no description failed.
- Built-in groups such as Administrators showed type "Other".

## [0.3.6] - 2026-11-14

### Added
- DNS records can be edited in place: value and TTL, saved in one step.
- SRV records can be created.

### Fixed
- MX priorities were stored byte-swapped, so DNS served priority 10 as 2560. Existing MX records made with EasyDC show their real (wrong) priority now; edit them to fix it.
- SRV records showed wrong numbers, for example `0 25600 34049` instead of `0 100 389`.
- A TXT value longer than 255 bytes was stored corrupted. It is split into several strings now.
- Deleting the last record of a name left an empty entry for that name in the directory. The name is removed with its last record now.
- Hostnames in CNAME, NS, PTR, MX and SRV records are checked. An invalid one, such as `a..example.com`, used to be stored as a corrupt record.

### Security
- Updated `rustix` to clear RUSTSEC-2026-0486.
- A new SQLite advisory (RUSTSEC-2026-0459) needs a crafted file planted next to the database, in a folder only the `easydc` user can write, so it does not affect EasyDC. It is ignored until sqlx ships the fixed SQLite.

## [0.3.5] - 2026-11-07

### Security
- Sessions now end after 8 hours without activity, and 24 hours after sign-in. They used to last until you logged out.
- Behind an HTTPS reverse proxy that sends `X-Forwarded-Proto`, the session cookie is marked `Secure`.

## [0.3.4] - 2026-10-29

### Changed
- Bootstrap and its icons are built into the binary instead of loaded from a CDN, so EasyDC works on networks with no internet access.

## [0.3.3] - 2026-10-28

### Fixed
- `easydc` ignored everything after `--port`, so a mistyped option there was never reported. Every argument is checked now.

## [0.3.2] - 2026-10-16

### Security
- Upgraded dependencies to clear every `cargo audit` advisory (8 vulnerabilities, 4 warnings), most of them from sqlx 0.7's unused TLS and MySQL code. sqlx is now 0.8 with SQLite support only.

### Changed
- The documentation site counts visits with Google Analytics, only for visitors who accept the cookie banner. EasyDC itself is unchanged and sends nothing anywhere.

## [0.3.1] - 2026-09-30

### Fixed
- **Enabling or disabling an account no longer resets its other settings.** The Users and Computers pages overwrote the account's whole flag value, silently clearing options such as *password never expires* — and disabling a domain controller from the Computers page would have broken it.

### Added
- **Fixes in the health check.** Stale computers, disabled accounts left in admin groups, accounts that need no password, and the machine account quota can now be fixed from the report. Each fix shows a preview first and is recorded in the audit log.
- **Automatic move from a manual install.** Installing the package takes over an existing hand-made EasyDC service, keeping its database and port. Nothing is deleted.
- **`easydc --version`** prints the installed version.

## [0.3.0] - 2026-09-24

### Added
- **Packages for Debian and Red Hat** — `.deb` and `.rpm` for x86_64 and arm64, installable from `repo.easysys.io`. The binary is statically linked, so it runs on any distribution. The service runs as its own `easydc` user, with its database in `/var/lib/easydc`. Moving from a manual install? Follow [the install guide](https://github.com/easysysio/EasyDC/blob/main/docs/install.md#moving-from-a-manual-install), or install 0.3.1, which does it for you.
- **Password policy page** for the domain's length, complexity, expiry, lockout and machine account quota settings, and a health check that flags a policy weaker than Samba's defaults.

### Fixed
- **Security:** a crafted name in a URL could make a delete act on the wrong object — including the domain's own DNS zone. Two admins removing each other at once could leave none and reopen setup; admin usernames could inject script into the Settings page; and changing a password did not end sessions from before 0.2.0.
- The privileged-group health check now follows nested groups.

## [0.2.3] - 2026-09-23

### Added
- **DNS zone creation and deletion** on the DNS page
  - **Add a zone** writes a primary, AD-integrated zone with secure dynamic update: the `dnsZone` object with its seven `dNSProperty` values, plus an apex node carrying SOA and NS. The SOA names this DC as primary server and `hostmaster.<domain>` as responsible party, and an NS record is written for **every** domain controller — they all replicate and serve the zone, so a single-NS zone would be inconsistent with every zone Samba creates
  - A zone created this way is served by the connected DC **immediately, with no restart**, and by the other DCs within seconds as replication reaches them — both measured against a live two-DC Samba domain
  - **Reverse zone** mode takes a network (`192.168.10` or `192.168.10.0/24`) and derives `10.168.192.in-addr.arpa`, previewed in the form as you type
  - Deleting a zone removes every node in it, leaf-first, behind a confirmation that requires typing the zone name. The tree-delete control is deliberately not used, so nothing outside the zone can be removed
  - The domain's own zone cannot be deleted — the button is withheld and the request refused, since it holds the SRV records members use to find a DC
  - Both actions are audited (`dns.zone_create`, `dns.zone_delete`)
  - The byte layouts are synthesised rather than copied from a neighbouring zone, so a zone with aging switched on cannot pass that setting to every zone created afterwards. Unit tests assert the SOA and property bytes against records a real Samba DC produced

### Changed
- **`--port` flag and `EASYDC_PORT`** to choose the listening port, so more than one instance can run at a time; the flag takes precedence over the environment variable, and `--help` lists the options

### Fixed
- Startup errors no longer panic. A port already in use, or one the process may not bind, now prints what happened and what to do and exits with status 1; a bad argument exits with 2. Previously a taken port surfaced as a Rust panic with a backtrace hint
- The DNS zone list rendered as a blank page when a template variable was set on one code path but not the other; both now go through the same renderer, and the template degrades to hiding delete buttons rather than failing

### Known limitation
- Deleting a zone does not take effect in Samba's running DNS server, which keeps answering authoritatively (NXDOMAIN) for the removed zone until `samba` is restarted on each DC. The confirmation and the docs say so. Zone *creation* is picked up live

## [0.2.2] - 2026-09-22

### Added
- **Settings** (`/settings`, linked from every page) for EasyDC's own sign-in accounts
  - **Change your password** — requires the current one, and signs out the account's other sessions so a changed password actually ends access elsewhere
  - **Administrator accounts** — add and remove the logins that administer EasyDC, so each person signs in as themselves and the audit log names who made a change. Removing one drops their sessions immediately
  - Refuses the two changes that would lock everyone out: deleting the account you are signed in as, and deleting the last administrator
  - Both successes and rejected attempts are written to the audit log (`settings.password_change`, `settings.admin_create`, `settings.admin_delete`)

## [0.2.1] - 2026-08-18

### Added
- **Domain health check** — a read-only diagnostics page (`/servers/:id/health`) that runs 13 checks against a DC and reports pass/warn/fail with an explanation and a remediation hint for each. Everything runs over the existing LDAP connection: no host access, no root, no process spawning, and nothing is written
  - *Time* — clock skew against the DC's `currentTime`, warning at 60s and failing at the 300s Kerberos limit
  - *Domain* — DC and site inventory, all five FSMO holders verified to still exist, domain/forest functional levels
  - *Replication* — inbound partner presence on the domain, configuration and schema partitions (skipped on single-DC domains)
  - *DNS* — the SRV set clients use to locate a DC (`_ldap`, `_kerberos`, `_kpasswd`, `_gc`, and their `_msdcs` forms), each DC's host record, and the per-DC `<GUID>._msdcs` CNAME, resolved across all three DNS partitions so either zone layout works
  - *Security* — LDAPS reachability and certificate expiry, `ms-DS-MachineAccountQuota`, anonymous LDAP access via `dSHeuristics`, unconstrained delegation outside the DCs, and disabled accounts still sitting in privileged groups
  - *Hygiene* — computer accounts inactive for over 90 days, and accounts flagged password-not-required or password-never-expires

## [0.2.0] - 2026-06-15

### Added
- **Password reset** — dedicated "Reset Password" action on each user with a "must change password at next logon" option (checked by default). Sets `unicodePwd` + `pwdLastSet` (requires LDAPS)
- **Account unlock & lockout status** — users now show a "Locked" badge (with bad-password-attempt count) when locked out; a one-click Unlock button clears `lockoutTime`
- **Audit log** — every state-changing action (users, password resets, unlocks, groups, OUs, computers, DNS, GPO, servers) is recorded with actor, action, target, server, result, and timestamp. Viewable at `/audit` with a client-side filter; failures are logged with their error detail
- Favicon (inline SVG, server-stack glyph in brand blue) shown on all pages

### Changed
- Login now records the authenticated username on the session so actions can be attributed in the audit log (`sessions.username` added via automatic migration)
- Templates are now registered together at startup so inheritance resolves regardless of file order

## [0.1.7] - 2026-06-14

### Fixed
- DNS records written by EasyDC are now valid live zone records. The `dnsp_DnssrvRpcRecord` header was malformed: a bogus 4-byte `0x60000000` flags field left `version = 0` and `rank = 0`, so Samba stored the value but reported the node as `Records=0` (record not served, not visible). The header now sets `version = 5` and `rank = 0xF0` (`DNS_RANK_ZONE`) per MS-DNSP
- `dwTtlSeconds` is now encoded and parsed as big-endian (MS-DNSP stores this field big-endian while the rest of the record is little-endian)
- Added unit tests asserting the record header byte layout and a full build→parse round-trip

## [0.1.6] - 2026-06-14

### Fixed
- PTR/NS/CNAME/MX/SRV records now use the correct DNS_COUNT_NAME (`dnsp_name`) wire format that Samba actually stores in the `dnsRecord` attribute: `[total_len][label_count][len]label…[0x00]`. The previous 0.1.5 encoding (`[len]dotted-string`) was rejected/garbled by Samba, so PTR records could not be added or displayed
- SRV record integer fields (priority/weight/port) now parsed as little-endian (NDR default), matching MX
- Added unit tests for DNS name encode/parse round-trip and exact byte layout

## [0.1.5] - 2026-06-14

### Fixed
- PTR (and NS, CNAME, MX, SRV) records now display correctly — Samba stores name targets using DNS_RPC_NAME format (1-byte length prefix + dotted string), not DNS wire-format label encoding; parsing and building updated accordingly
- `dnsRecord` attribute lookup is now case-insensitive — ldap3 may return it as `dnsrecord` depending on the server response
- MX record priority now parsed as little-endian (matching MS-DNSP spec)
- SRV record target field updated to use DNS_RPC_NAME parsing

## [0.1.4] - 2026-06-14

### Fixed
- DNS add/delete errors are now shown on the zone page instead of being silently ignored
- PTR record form now shows the correct hint: node name should be the last octet only (e.g. `53`), not the full FQDN

## [0.1.3] - 2026-05-16

### Added
- OU management — tree view of all Organizational Units with depth-based indentation
- Create OU with optional description, choosing any existing OU or domain root as parent
- Rename OU in place via LDAP modifydn
- Delete OU (enforced empty by LDAP — fails gracefully if objects remain)
- Move any AD object (user, group, computer) to a different OU by sAMAccountName
- OU Management card added to the server detail page

## [0.1.2] - 2026-05-16

### Fixed
- DNS zone page no longer shows a blank page (Tera does not support `loop.parent`, template rewritten to avoid nested loop indices)
- DNS record delete now works correctly — replaced broken modal-per-record approach with inline confirm dialog

## [0.1.1] - 2026-05-16

### Fixed
- Templates are now embedded in the binary at compile time — no `templates/` directory required on the server
- DNS zone discovery now correctly searches `CN=MicrosoftDNS,DC=DomainDnsZones` (Samba's actual DNS partition)
- Internal DNS zones (`RootDNSServers`, `_msdcs`, `..TrustAnchors`) are filtered from the zone list
- Server now logs `0.0.0.0:3000` instead of `localhost:3000`

### Added
- Version number displayed in the bottom-right corner of every page
- GitHub Actions workflow to build and publish releases for Linux x86_64 and ARM64
- Release notes pulled automatically from CHANGELOG.md
- OpenSSL vendored for cross-compilation (no system OpenSSL required)

### Changed
- README updated with binary download instructions and systemd service setup
- Rust is no longer listed as a requirement (pre-built binaries provided)

## [0.1.0] - 2026-05-16

### Added
- Initial release
- Web-based management GUI for Samba Active Directory Domain Controllers
- Multi-server dashboard — add, edit, and delete DC server connections
- User management — create, edit, enable/disable, and delete AD users
- Group management — create security/distribution groups, manage memberships
- Computer management — view, enable/disable, and remove computer accounts
- DNS management — browse AD-integrated zones, add and delete records (A, AAAA, CNAME, MX, TXT, NS, PTR)
- GPO management — create GPOs, manage status flags, link/unlink to OUs
- First-run setup wizard with admin account creation
- Session-based authentication
