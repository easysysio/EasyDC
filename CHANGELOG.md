# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Password policy page** (`/servers/:id/policy`) for the domain-wide settings `samba-tool domain passwordsettings` manages: minimum length, complexity, history, maximum and minimum age, lockout threshold, duration and attempt window, and `ms-DS-MachineAccountQuota`
  - Durations are stored as negative 100-nanosecond intervals and converted to days and minutes in both directions, with "never" round-tripping correctly
  - Combinations the directory would refuse — a minimum age at or beyond the maximum, an attempt window longer than the lockout duration — are rejected before anything is written
  - The complexity flag is set without disturbing the other bits of `pwdProperties`
  - The whole resulting policy is written to the audit log as `policy.update`, so a later "who loosened this?" has an answer
- **Password policy health check** — reports the current settings and fails on no minimum length, warns when weaker than Samba's own defaults (7 characters, complexity required, 42-day expiry)

### Packaging
- **`.deb` and `.rpm` packages** for x86_64 and arm64, built on native runners by the release workflow on every `v*` tag and attached to the GitHub Release. [EasyDC-repo](https://github.com/easysysio/EasyDC-repo)'s `github2repo.sh` publishes them, signed, to `repo.easysys.io/easydc`
- The packages install `/usr/bin/easydc` and an `easydc.service` that runs as a dedicated `easydc` user with its database in `/var/lib/easydc` (mode `0700`, since it holds every DC's bind password). The port can be set in `/etc/default/easydc` or `/etc/sysconfig/easydc`
- Upgrades restart the service only if it was running; removal stops and disables it but leaves the user and the database in place
- The user and directory match the earlier manual install instructions, so an existing database carries over; the install guide lists the two files to remove first, since a unit in `/etc/systemd/system` would otherwise shadow the packaged one
- The release workflow now refuses a tag that does not match the version in `Cargo.toml`, rather than publishing packages that carry the wrong version
- The bare `easydc-linux-x86_64` and `easydc-linux-arm64` binaries are still attached to each release

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
