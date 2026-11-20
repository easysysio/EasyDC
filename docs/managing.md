# Managing the domain

Every change below is written straight to the domain controller over LDAP, and recorded
in the [audit log](#audit-log) with who made it and whether it succeeded.

## Users

The left pane lists the domain's **OUs and containers**, as in Active Directory Users and
Computers, with how many users each holds. Pick one to see only its users; turn on
**Include nested OUs** to add the users in the OUs below it. The domain name at the top
shows everyone. Containers with no users (such as `Computers`) and system ones (such as
`System`) are left out.

Above the list, **All / Enabled / Disabled / Locked / Expired** filter by account status,
with a count for each, and the search box narrows the list as you type: it looks in the
username, display name, description, email, job title and department.

**Several users at once:** tick the users (the box in the header ticks every user shown),
and a bar appears to **enable**, **disable**, **move** them to another OU or container, or
**add them to a group**. If some of them fail, the page says which and why; the others
are done. Each user's change is a separate line in the audit log.

- **Move**, in a user's **⋯** menu with *Reset password* and *Delete*, moves one user to
  another OU or container. The user keeps their name, groups and settings.
- EasyDC will not disable, delete or move the account it signs in to the DC with, since
  that would lock it out. To do it anyway, first change the server's bind account with
  **Edit** on the dashboard.
- **Create** a user with a username, first and last name, email and initial password. The
  user is created in the OU or container you are looking at, or in `Users` when the whole
  domain is shown.
- **Edit** names, email and description, **enable or disable** the account, or **delete**
  it. The description is also a column in the list.
- **Profile**: job title, department, office, phone, mobile and manager, in both the
  Add and Edit dialogs. The manager field suggests usernames as you type. Clearing a
  field removes the value from the directory.
- **Account expires** sets the last day the account can be used, for contractors and
  other temporary accounts. Leave it blank for an account that never expires. The day
  ends at midnight UTC. The list shows **Until *date*** on accounts with an end date,
  and **Expired** once it has passed. An expired account cannot log in even though it
  is still enabled; set a later date, or clear it, to let the user back in.
- **Reset password** sets a new password, with *must change password at next logon*
  checked by default.
- **Unlock** clears a lockout. Locked accounts carry a **Locked** badge in the list, with
  the count of bad password attempts.

!!! note
    Anything that writes a password — creating a user, resetting a password — needs the
    server added with an `ldaps://` URL.

## Groups

Create **security** or **distribution** groups with a **global**, **domain local** or
**universal** scope, edit and delete them, and manage membership.

As on the Users page, the left pane lists the OUs and containers with how many groups each
holds, including `Builtin` for Windows' own groups. Pick one to see its groups, with
**Include nested OUs** for the ones below. A new group is created in the OU you are
looking at, or in `Users` when the whole domain or `Builtin` is shown.

- **Members**: open a group to see everyone in it — users, computers, other groups, and
  the built-in identities Samba puts in its own groups, such as *Authenticated Users*.
  The page also lists the groups this group is a member of.
- **Add** a user, computer or group by name; the box suggests names as you type. A
  computer can be given with or without its trailing `$`.
- **Groups inside groups** follow Windows' rules: a global group can only contain global
  groups, a universal group global and universal ones, and a domain local group any of
  them. A group cannot contain itself, and EasyDC refuses a nesting that would make a
  loop (A inside B inside A).
- **Change scope or type** in the Edit dialog. As in Windows, global and domain local
  change only through universal, and a change that would break one of the group's
  memberships is refused with the reason. Built-in groups (Administrators, Domain Admins
  and the like) keep their scope and type.

When an action is refused, the reason is shown on the page and recorded in the audit log.

## Search

Every list (users, groups and a group's members, computers, DNS zones and records,
Group Policy Objects and OUs) has a search box that narrows it as you type. It
looks in the columns shown, such as name, description, type, hostname or GUID; with
several words, a row must contain all of them.

## Computers

List the computer accounts in the domain, **enable or disable** them, and **delete**
accounts for machines that are gone.

## DNS

Browse the domain's **AD-integrated DNS zones** — the ones stored in the directory under
`DC=DomainDnsZones` — and add, edit or delete records:

`A` · `AAAA` · `CNAME` · `MX` · `TXT` · `NS` · `PTR` · `SRV`

An **SRV** record's name is the service and protocol, such as `_sip._udp`, and its value
is priority, weight, port and target: `10 50 5060 sip.example.com`. A **TXT** value longer
than 255 bytes, such as a DKIM key, is split into several strings, which resolvers join.

**Edit** (the pencil) changes a record's value and TTL in one step: if the save fails, the
old record stays. Everything else about the record is kept, including whether a client
registered it dynamically. To change a record's name or type, add a new one and delete the
old. If someone else changed the record after your page loaded, nothing is saved and you
are told to check again.

A search box above each list finds a zone by name, or a record by its name or value.
Inside a zone you can also show a single record type.

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

## Replication

**Replication** shows, for each domain controller, which DC it receives each partition from
(domain, configuration, schema and the two DNS partitions), when that last worked, and the
error if it failed — what `samba-tool drs showrepl` shows, read over LDAP.

- **OK**: the last attempt succeeded. Samba replicates every 5 minutes even when nothing
  changed, so the last success is normally minutes old.
- **Check**: no success for over an hour, the last attempt reported an error, or
  automatic replication is disabled for that link.
- **Failing**: failed attempts in a row, with the error in words (*the RPC server is
  unavailable*, *DNS lookup failure*…), or no success for over a day.
- A DC with **no inbound partners** receives nothing from the others and drifts apart.

EasyDC reads each DC's own records, so it connects to every DC by its DNS name with the
server's account and TLS setting. A DC it cannot reach is shown as such, with the reason,
and does not hold up the rest of the page. To force a sync, run
`samba-tool drs replicate <to-DC> <from-DC> <partition DN>` on a DC.

## Password policy

**Password Policy** on a server edits the domain-wide settings that
`samba-tool domain passwordsettings` manages — they apply to every account in the domain,
unlike [Settings](#easydc-administrators), which covers EasyDC's own logins.

| Setting | Notes |
|---|---|
| **Minimum length** | 0 allows an empty password. Samba's provisioning default is 7 |
| **Complexity** | Mixed case, digits or symbols, and no part of the username |
| **History** | How many previous passwords cannot be reused; 0 allows immediate reuse |
| **Maximum age** | 0 means passwords never expire |
| **Minimum age** | How long before a password may be changed again |
| **Lockout threshold** | Bad attempts before lockout; **0 disables lockout**, so guessing is unlimited |
| **Lockout duration** | 0 means locked until an administrator unlocks |
| **Attempt window** | Must not be longer than the lockout duration |
| **Machine account quota** | `ms-DS-MachineAccountQuota` — machines a normal user may join; the default of 10 is a known privilege-escalation path |

Durations are stored as negative 100-nanosecond intervals, which EasyDC converts to days and
minutes in both directions. A value set elsewhere with finer precision — a 12-hour minimum
age, say — is shown rounded down, and **kept exactly as stored** unless you change that
field. With lockout enabled, the attempt window must be at least 1 minute: 0 would mean a
failed attempt is never forgotten. Combinations the directory would refuse — a minimum age longer
than the maximum, an attempt window longer than the lockout duration — are rejected before
anything is written, and the whole policy is recorded in the audit log as `policy.update`.

### Policies for groups and users

Below the domain policy, **Policies for groups and users** sets different rules for some
accounts: longer passwords for administrators, no expiry for service accounts. These are
Samba's *password settings objects* (PSOs), the same ones
`samba-tool domain passwordsettings pso` manages.

- **Add policy** starts from the domain policy's values; change what should differ. Each
  policy has a **precedence**: when several apply to a user, the lowest number wins, and a
  policy applied to the user directly beats one applied through a group.
- **Apply** a policy to users or to **global security groups** — the only groups Windows
  applies them through, so EasyDC refuses universal, domain local and distribution groups
  rather than let the policy be silently ignored. Remove a user or group with its **×**.
  A policy applied to nobody has no effect.
- **Which policy applies to** answers for one user: the policy the DC computes for it, or
  the domain policy.

These policies need the domain functional level at Windows 2008 or higher (Samba 4.9 and
newer on every DC). On an older domain the section explains how to raise it instead.
Changes are recorded in the audit log as `pso.create`, `pso.update`, `pso.delete`,
`pso.apply` and `pso.unapply`.

## EasyDC administrators

**Settings** in the top bar manages the accounts that sign in to *EasyDC* — not domain
users. The first one is created by the setup wizard.

- **Change your password** — needs your current one. Your other sessions are signed out,
  so a changed password actually ends access anywhere else you were signed in.
- **Add an administrator** — so each person signs in as themselves and the audit log
  names who made a change. Every administrator has full access; there are no roles yet.
- **Remove an administrator** — their sessions are dropped immediately.

Usernames may contain letters, digits and `. _ - @`. You cannot delete the account you are
signed in as, and at least one administrator always remains — even when two administrators
remove each other at the same moment.

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
