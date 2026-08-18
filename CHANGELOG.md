# Changelog

All notable changes to this project will be documented in this file.

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
