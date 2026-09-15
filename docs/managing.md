# Managing the domain

Every change below is written straight to the domain controller over LDAP, and recorded
in the [audit log](#audit-log) with who made it and whether it succeeded.

## Users

- **Create** a user with a username, first and last name, email and initial password.
- **Edit** names and email, **enable or disable** the account, or **delete** it.
- **Reset password** sets a new password, with *must change password at next logon*
  checked by default.
- **Unlock** clears a lockout. Locked accounts carry a **Locked** badge in the list, with
  the count of bad password attempts.

!!! note
    Anything that writes a password — creating a user, resetting a password — needs the
    server added with an `ldaps://` URL.

## Groups

Create **security** or **distribution** groups, edit and delete them, and manage
membership: open a group to see its members, add users, and remove them.

## Computers

List the computer accounts in the domain, **enable or disable** them, and **delete**
accounts for machines that are gone.

## DNS

Browse the domain's **AD-integrated DNS zones** — the ones stored in the directory under
`DC=DomainDnsZones` — and add or delete records:

`A` · `AAAA` · `CNAME` · `MX` · `TXT` · `NS` · `PTR`

Internal zones such as `_msdcs` and `RootDNSServers` are hidden from the list. Errors
returned by the server are shown on the page rather than swallowed.

## Group Policy

Create **Group Policy Objects**, set their status (enabled, or user / computer settings
disabled), delete them, and **link or unlink** them to OUs.

!!! info "Metadata only"
    EasyDC manages the GPO objects in the directory: name, status and links. The policy
    *settings* themselves — registry values, scripts — live in SYSVOL on the domain
    controller and are not edited from EasyDC.

## Organizational Units

Browse the OU tree, **create**, **rename** and **delete** OUs, and **move** users,
groups and computers from one OU to another.

## Audit log

The **Audit Log** in the top bar shows the **500 most recent actions** across all
servers, newest first, with a filter box for narrowing by actor, action or target.

Each entry records the time, the EasyDC user who acted, the action (for example
`user.reset_password` or `dns.add_record`), its target, the server, and **success** or
**failure**. Failures keep the error the server returned, so a rejected change can be
diagnosed after the fact.
