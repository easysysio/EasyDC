# Changelog

All notable changes to this project will be documented in this file.

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
