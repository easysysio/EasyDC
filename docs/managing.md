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

### Creating a zone

**Add a zone** creates a primary, AD-integrated zone with secure dynamic update — the same
kind of zone `samba-tool dns zonecreate` produces. The DC you are connected to serves it
**immediately, without restarting samba**; the other DCs follow within seconds, as normal
directory replication reaches them.

Tick **Reverse zone** to enter a network instead of a name: `192.168.10` or
`192.168.10.0/24` both create `10.168.192.in-addr.arpa`. The page shows the resulting zone
name as you type.

The zone's SOA names this DC as the primary server and `hostmaster.<your domain>` as the
responsible party. An **NS record is created for every domain controller** in the domain,
not just the one you are connected to — zones live in a partition replicated to all of
them, so they all answer for the zone.

### Deleting a zone

Deleting a zone removes it and **every record in it**. You are asked to type the zone name
to confirm.

!!! warning "A deleted zone keeps answering until samba restarts"
    Deletion removes the zone from the directory, but Samba's DNS server keeps the zone in
    memory and goes on answering for it **authoritatively** — returning NXDOMAIN for every
    name in it — until `samba` is restarted on each DC. Until then the name is
    black-holed rather than forwarded upstream. Creation does not have this problem; only
    deletion does.

The domain's own zone cannot be deleted from EasyDC. It holds the SRV records every member
uses to find a domain controller, so the button is not offered and the request is refused
if made directly.

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

## EasyDC administrators

**Settings** in the top bar manages the accounts that sign in to *EasyDC* — not domain
users. The first one is created by the setup wizard.

- **Change your password** — needs your current one. Your other sessions are signed out,
  so a changed password actually ends access anywhere else you were signed in.
- **Add an administrator** — so each person signs in as themselves and the audit log
  names who made a change. Every administrator has full access; there are no roles yet.
- **Remove an administrator** — their sessions are dropped immediately.

You cannot delete the account you are signed in as, and at least one administrator always
remains.

!!! note "Separate from the directory"
    These accounts live in EasyDC's own database, with bcrypt-hashed passwords. Resetting a
    *domain* user's password is under [Users](#users).

## Audit log

The **Audit Log** in the top bar shows the **500 most recent actions** across all
servers, newest first, with a filter box for narrowing by actor, action or target.

Each entry records the time, the EasyDC user who acted, the action (for example
`user.reset_password`, `dns.zone_create` or `settings.admin_create`), its target, the server, and **success** or
**failure**. Failures keep the error the server returned, so a rejected change can be
diagnosed after the fact.
