# Managing the domain

Every change below is written straight to the domain controller over LDAP, and recorded
in the [audit log](#audit-log) with who made it and whether it succeeded.

## Users

The left pane lists the domain's **OUs and containers**, as in Active Directory Users and
Computers, with how many users each holds. Pick one to see only its users; turn on
**Include nested OUs** to add the users in the OUs below it. The domain name at the top
shows everyone. Containers with no users (such as `Computers`) and system ones (such as
`System`) are left out.

Above the list, **All / Enabled / Disabled / Locked / Expired / Password to change** filter by account status,
with a count for each, and the search box narrows the list as you type: it looks in the
username, display name, description, email, job title and department.

**Several users at once:** tick the users (the box in the header ticks the page; then
**Select all** in the bar picks every user that matches the search and filter), and a bar
appears to **enable**, **disable**, **move** them to another OU or container, or
**add them to a group**. If some of them fail, the page says which and why; the others
are done. Each user's change is a separate line in the audit log.

More than 100 users are sent to the DC 100 at a time, with a progress bar; keep the page
open until it finishes. A DC makes about 25 to 30 changes a second, so 2,000 users take
about a minute and a half. Users that are already as asked (enabling an enabled user)
take no time.

**Export** downloads the users in the view (the OU, nested or not, and the status filter)
as a CSV file for a spreadsheet, with their names, email, profile, manager, account expiry,
OU and whether they are enabled. A value that starts like a spreadsheet formula (`=`, `+`,
`-`, `@`) gets a `'` in front, so opening the file runs nothing.

**Import** creates users from a CSV file. The first line names the columns: **Username** is
needed; First name, Last name, Email, Password, Description, Job title, Department, Office,
Phone, Mobile, Manager, Account expires (YYYY-MM-DD) and OU are read when there; other
columns are ignored. An exported file has these headings. Commas, semicolons (as Excel
saves in some countries) and tabs all work, in UTF-8 or Windows' own encoding.

- EasyDC checks the file first and changes nothing: it lists the users it will create, the
  rows it cannot (with the line and why), and the users already in the domain, which are
  left unchanged. Import only creates users; it does not change existing ones.
- Users go to the OU picked in the dialog, or to the one a row names (a path such as
  `Sales/Europe`, or a DN).
- A row without a password gets the one given in the dialog. *Users must change their
  password at first sign-in* is on by default.
- A manager can be an existing user or one the same file creates; EasyDC creates managers
  first.
- Users are created 25 at a time with a progress bar, about 3 a second, since setting a
  password is the slow part: 1,000 users take about 5 minutes. Each user is a line in the
  audit log.

- **Move**, in a user's **⋯** menu with *Reset password* and *Delete*, moves one user to
  another OU or container. The user keeps their name, groups and settings.
- EasyDC will not disable, delete, move or reset the password of the account it signs in
  to the DC with, since that would lock it out. To do it anyway, first change the server's
  bind account with **Edit** on the Servers page. To change that account's password, set it
  on the DC, then put the new one in the server's settings.
- **Create** a user with a username, first and last name, email and initial password. The
  user is created in the OU or container you are looking at, or in `Users` when the whole
  domain is shown. A username cannot contain `" / \ [ ] : ; | = , + * ? < > @`; accents,
  Hebrew and other letters are fine. If the place already holds someone with the same first
  and last name, the new user's directory entry is named *John Smith (jsmith2)*; the display
  name stays *John Smith*.
- **Edit** names, email and description, **enable or disable** the account, or **delete**
  it. The description is also a column in the list.
- **Profile**: job title, department, office, phone, mobile and manager, in both the
  Add and Edit dialogs. The manager field suggests usernames as you type. Clearing a
  field removes the value from the directory.
- **Groups**, a tab in the Edit dialog, lists the groups the user is directly in, with the
  primary group (usually Domain Users) marked. Add a group by name, or remove one with ×;
  each change is made at once. The primary group is kept on the user rather than in the
  group's members, so it is not removed here. Adding and removing need Edit on Groups.
- **Account expires** sets the last day the account can be used, for contractors and
  other temporary accounts. Leave it blank for an account that never expires. The day
  ends at midnight UTC. The list shows **Until *date*** on accounts with an end date,
  and **Expired** once it has passed. An expired account cannot log in even though it
  is still enabled; set a later date, or clear it, to let the user back in.
- **Reset password** sets a new password, with *must change password at next logon*
  checked by default. Until the user does, the list shows **Must change password**. A
  password older than the maximum password age (from the domain policy, or the user's
  PSO) shows **Password expired**. Either way the user cannot sign in with their old
  password; on a PC, Windows asks for a new one.
- **Password**, a tab in the Edit dialog, shows when the password was last set and when it
  expires (by the domain policy or the user's PSO), and has three switches: *User must
  change password at next sign-in*, *User cannot change password* and *Password never
  expires*. As in Windows, *must change* cannot go with either of the other two, and
  EasyDC does not ask its own bind account to change its password. *Cannot change
  password* is not an account flag in Active Directory but two entries in the user's
  permissions that deny the Change Password right to Everyone and to the user; EasyDC
  changes only those entries, and turning it off restores the defaults.
- **Unlock** clears a lockout. Locked accounts carry a **Locked** badge in the list, with
  the count of bad password attempts. When the lockout duration runs out the account
  unlocks by itself, and the badge goes with it.

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

## Search and pages

Every list (users, groups and a group's members, computers, DNS zones and records,
Group Policy Objects and OUs) has a search box that narrows it as you
type. It looks in the columns shown, such as name, description, type, hostname or GUID;
with several words, a row must contain all of them.

A list longer than 25 rows is shown a page at a time, with the page numbers and a choice
of 25, 50, 100 or 250 rows per page under it; your choice is kept for every list. The
search covers the whole list, not just the page shown. After an action, such as disabling
a user, the list comes back on the same page with the same search.

## Computers

Computers are listed by **OU and container**, as users are, with **Include nested OUs** to
add the ones below. **Enable or disable** a computer account, **move** it to another OU, or
**delete** the account of a machine that is gone. Tick computers to enable, disable or
move many at once; a big selection is sent in parts, as on the Users page.

Computers are added by joining them to the domain from the computer itself. **Domain
controllers** are marked and left alone: EasyDC does not disable, move or delete a DC's
account, since that would stop it working as one. To remove a DC, demote it first
(`samba-tool domain demote` on that DC). Domain Controllers is not offered as a place to
move other computers to, because its policies are meant for DCs.

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

Creating a GPO makes the directory object and its SYSVOL folder (`Machine`, `User` and
`GPT.INI`), with folder permissions that match the object, as `samba-tool gpo create` does.
If any step fails, both are removed again.

Deleting a GPO removes the object and its folder, **including any settings in it**. EasyDC
refuses to delete the two default GPOs, or a GPO that is still linked to an OU.

!!! info "What this needs"
    - EasyDC must reach **TCP port 445** on the PDC emulator, and the bind account must be
      able to write to SYSVOL. Without port 445, EasyDC will not create a GPO, because a GPO
      with no folder fails on clients.
    - Samba does not replicate SYSVOL. EasyDC writes to the PDC emulator only, so use your
      own SYSVOL sync to copy new folders to the other DCs.
    - EasyDC does not edit policy settings (registry values, scripts). Use the Group Policy
      Management Console for that.

## Organizational Units

Browse the OU tree, **create**, **rename** and **delete** OUs, and **move** users,
groups and computers from one OU to another.

### Delegation

**Delegation** (on the Organizational Units page, or the shield next to an OU) lets a group
do a job in an OU without making its members domain admins: a help desk that resets
passwords, say. It is what `samba-tool dsacl` and Windows' Delegation of Control wizard do.
Only admins can change it.

- The page lists, for the OU you pick, what each group may do there beyond the defaults:
  a task EasyDC knows by name, or other rights in words ("Read and write gPLink"). The
  rights every OU gets from the domain's defaults, such as Domain Admins' full control,
  are under *Built-in access*.
- **Delegate…** gives a security group one of these tasks: create, delete and manage
  users; reset passwords and unlock accounts; create, delete and manage groups; change
  group membership; create, delete and manage computers; link GPOs.
- What a group is given applies in the OU and the OUs inside it, from any tool, not only
  EasyDC. A right from a parent OU shows as such, and is removed on the OU it was set on.
- The remove button takes away a task, or the other rights, set on that OU.

## Domain controllers

**Domain Controllers** lists each DC with its DNS name, its site, and the FSMO roles it
holds. *EasyDC connects here* marks the DC this server entry signs in to.

Every DC can do almost everything, but seven jobs, the **FSMO roles**, are done by one DC
at a time: the PDC emulator, RID master, infrastructure master, schema master, domain
naming master, and the masters of the two DNS partitions. The page says what each does.
Move them off a DC before you take it out of service.

- **Move…** next to a role moves it to another DC, and **Move all roles here** next to a
  DC moves every role it does not hold yet. Only admins can do this.
- Both DCs must be running: the DC that is to hold a role asks the one that holds it to
  hand it over. A move takes a few seconds; the PDC emulator takes about 15.
- The DNS partition roles are changed on the DC that holds them, and the others learn of
  it as they replicate. If the DC EasyDC reads from has not seen the change yet, the page
  says so; it catches up within a few minutes.
- A role whose holder no longer exists is marked so. It cannot be moved, only seized, on
  a DC with `samba-tool fsmo seize --role=<role>`, and only once the old DC is gone for
  good: seizing a role from a DC that comes back splits the domain.

### Functional level

The **Functional level** card shows the level of the domain and the forest, and the highest
level each DC can run at. A DC's highest level comes from `ad dc functional level` in its
`smb.conf`. The level also shows with the server's details on the Servers page and the server's Overview, and each
DC's level is in the DC table.

Samba allows a raise only from a shell on a DC, so EasyDC guides it instead of making it.
Admins choose **How to raise…** and a level, up to Windows Server 2016. EasyDC reads the
domain and lists only the steps that level still needs, with the exact commands and the DC
to run each one on:

1. Back up every DC.
2. Set `ad dc functional level` on any DC below that level, and restart Samba there.
3. Run `samba-tool domain schemaupgrade` and `functionalprep`, if the directory needs them.
4. Run `samba-tool domain level raise`, on one DC only. It replicates to the others.
5. Restart Samba on every DC, one at a time.

Then choose **Check the level** to see the new level.

!!! warning "A raise cannot be undone"
    Going back means restoring every DC from backup, together. After a raise, a DC below the
    new level can no longer join. Samba 4.19 calls its support for levels above 2008 R2
    partial, so test first and keep every DC on the same version.

### Removing a dead DC

When a DC is gone for good (its server died, or it was switched off without being demoted),
the other DCs keep trying to replicate with it and DNS keeps sending clients to it.
**Remove…** next to that DC cleans up what it left behind, like
`samba-tool domain demote --remove-other-dead-server`. Only admins can do this.

- The dialog first lists everything that will be deleted: replication connections from
  it, its SYSVOL replication entries, its Samba DNS account, its computer account, its
  server object, and the DNS records that point at it. Type the DC's name to confirm.
- EasyDC refuses while the DC still answers on the network, at its name or at the address
  its name has in DNS; while it holds an FSMO role (seize the role on a live DC first); and
  for the DC EasyDC itself connects to. If its name points at an address another machine
  now has, change or remove that A record on the DNS page first.
- An address the DC's name shares with another DC is never removed from the names all
  DCs share, such as the domain's own name.
- A DC that is still running is removed by demoting it, on itself:
  `samba-tool domain demote`.

## Replication

**Replication** shows, for each domain controller, which DC it receives each partition from
(domain, configuration, schema and the two DNS partitions), when that last worked, and the
error if it failed — what `samba-tool drs showrepl` shows, read over LDAP.

- **OK**: the last attempt succeeded. Samba replicates every 5 minutes even when nothing
  changed, so the last success is normally minutes old.
- **Check**: no success for over an hour, the last attempt reported an error,
  automatic replication is disabled for that link, or a new link has not run yet.
- **Failing**: failed attempts in a row, with the error in words (*the RPC server is
  unavailable*, *DNS lookup failure*…), or no success for over a day.
- A DC with **no inbound partners** receives nothing from the others and drifts apart.
  Just after a second DC joins, the first DC shows this for a few minutes, then its new
  links show *Not run yet*; both clear by themselves within about 10 minutes.

EasyDC reads each DC's own records, so it connects to every DC by its DNS name with the
server's account and TLS setting. A DC it cannot reach is shown as such, with the reason,
and does not hold up the rest of the page. To force a sync, run
`samba-tool drs replicate <to-DC> <from-DC> <partition DN>` on a DC.

## Sites and subnets

A **site** is a place with a fast network, such as an office. A computer finds its site
from its address, using the **subnets**, and then signs in at a DC in that site rather than
across a slow link. **Site links** say which sites replicate with each other, at what cost
and how often. A new domain has one site, *Default-First-Site-Name*, and one link,
*DEFAULTIPSITELINK*.

- **Sites** show their DCs, subnets and site links. **Add Site** asks for a name and the
  site link to put it in, so it replicates with the others. A site name can hold letters,
  digits and hyphens only, since each DC publishes its site in DNS.
- **Delete** a site that holds no DC. It is taken out of its site links, and its subnets
  stay with no site until you give them one. A site that holds a DC shows *Holds a DC,
  so it stays*.
- **Move…** next to a DC moves it to another site: when the DC has moved, or its site was
  set wrong when it joined. Samba updates the DC's DNS records for the new site at its
  next DNS update, within about 10 minutes.
- **Subnets** are written as an address and a prefix length, such as `10.1.0.0/16` or
  `2001:db8:10::/48`. EasyDC refuses an address with host bits set (`10.1.2.3/16`) and says
  which subnet was meant. A subnet with no site is marked **No site**.
- **Site links**: tick the sites in the link, and set its **cost** (lower is preferred;
  100 is the default) and how often it **replicates** (15 minutes to a week, in steps of
  15; every 3 hours is the default). EasyDC will not leave a site in no link at all, since
  its DCs would then not replicate with the other sites. Within a site, DCs replicate
  within seconds of a change, whatever the links say.

## Password policy

**Password Policy** on a server edits the domain-wide settings that
`samba-tool domain passwordsettings` manages — they apply to every account in the domain,
unlike [Settings](#easydc-accounts), which covers EasyDC's own logins.

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
newer on every DC). On an older domain, raise it under [Functional level](#functional-level).
Changes are recorded in the audit log as `pso.create`, `pso.update`, `pso.delete`,
`pso.apply` and `pso.unapply`.

## Reports

**Reports** on a server's page answers the questions an admin asks every week. Reports are
read-only, anyone signed in can see them, and each downloads as a CSV file.

| Report | What it lists |
|---|---|
| **Inactive accounts** | Enabled users and computers with no sign-in for a number of days you choose, 90 by default |
| **Passwords expiring** | Enabled users whose password expires within a number of days, 14 by default, or already has. Password policies for groups are included |
| **Passwords that never expire** | Enabled users whose password is set never to expire |
| **Locked, disabled or expired** | Users who cannot sign in, and why |
| **Privileged group members** | Everyone in Domain, Enterprise and Schema Admins, Administrators, the Account, Server, Backup and Print Operators, and Group Policy Creator Owners, and how they got there |
| **Empty groups** | Groups with no members |

- **The last sign-in can be up to 14 days behind**, because domain controllers only
  replicate it about that often. So the inactive report starts at 14 days.
- **Primary groups count.** They are not in a group's member list, so other tools can show
  a group as empty, or miss a Domain Admin. These reports include them.
- **Built-in accounts and groups** that are always disabled or empty, such as `krbtgt`,
  `Guest` and Print Operators, are left out of the disabled and empty reports.

## SPNs

**SPNs** on the server page lists every service principal name in the domain, with the
account it is on. An SPN tells Kerberos which account runs a service, such as
`HTTP/web.example.com`. Filter the list by SPN or account.

- **Add SPN** — enter the user or computer and the SPN, written as `service/host`,
  `service/host:port` or `service/host:port/name`. EasyDC refuses an SPN that is already
  on any account in the domain, and names that account.
- **Remove** — asks first, and warns when it is a computer's `HOST/` SPN, which sign-ins
  and file sharing rely on.
- **Duplicate** marks an SPN found on more than one account. Kerberos sign-ins to that
  service can fail until you remove it from all but one.

The SPNs that keep the domain working show a lock and cannot be changed here: those of
domain controllers, `krbtgt` and other critical system accounts, and the `DNS/` SPN of
Samba's `dns-<host>` account.

Changing a user's SPN needs Edit on Users, and a computer's needs Edit on Computers.
Changes are recorded in the audit log as `spn.add` and `spn.remove`.

## EasyDC accounts

**Settings** in the top bar manages who can sign in to *EasyDC*. The first account is
created by the setup wizard, and is a local admin.

- **Change your password** — under your name in the top bar. It needs your current one.
  Your other sessions are signed out, so a changed password actually ends access anywhere
  else you were signed in.
- **Add an account** — so each person signs in as themselves and the audit log names who
  made a change. Choose the kind (below) and what they may change.
- **Change permissions** — the shield button next to an account. It applies from that
  person's next click.
- **Remove an account** — their sessions are dropped immediately.

Only admins can add, change or remove accounts. You cannot change or delete the account
you are signed in as.

### Local and domain accounts

- A **local account** has a username and password kept in EasyDC's own database (bcrypt
  hashed). Usernames may contain letters, digits and `. _ - @`.
- A **domain account** is added by choosing a server and typing a domain username. EasyDC
  keeps no password for it: signing in checks the password with that server's DC. Its
  EasyDC name is `user@domain`, such as `jsmith@example.com`, and it can sign in with
  that, with `jsmith`, or with `EXAMPLE\jsmith`. If a local account has the same short
  name, the short name signs in as the local one.

A domain account that is disabled, expired or locked out in the domain cannot sign in to
EasyDC, nor one whose password must be changed first; the sign-in page says which. Its
password is changed in the domain, not in EasyDC. If its server is removed from EasyDC, it
cannot sign in until an admin adds it again.

At least one **local** admin always remains — even when two admins remove each other at
the same moment — so someone can sign in while the DC is down. Every sign-in, and every
refused one, is recorded in the audit log as `auth.sign_in`.

### Two-factor sign-in

A local account can also ask for a code from an authenticator app, such as Google
Authenticator, Microsoft Authenticator, 1Password or Bitwarden. Click **your name** in the
top bar, then **Two-factor sign-in → Set up**, enter your password, scan the QR code and
type the code it shows.

EasyDC then shows **10 recovery codes, once**. Keep them away from your phone: each signs
you in one time if the phone is lost. After 5 wrong codes, the account takes no codes for
15 minutes.

To move to a new phone, turn two-factor off on the same page and set it up again.

**Admins** can:

- turn on **Require it for local admins** in **Settings → Two-factor**. A local admin without it must set it up at their
  next click, before doing anything else;
- reset it for someone who lost both their phone and recovery codes, with the shield button
  beside the account. That person is signed out, and signs in with the password alone until
  they set it up again.

Domain accounts are not covered, even when they are admins: they sign in with their domain
password only.

If the only admin is locked out, reset it on the EasyDC host:

=== "Package"

    ```bash
    sudo -u easydc sh -c 'cd /var/lib/easydc && easydc --reset-2fa alice'
    ```

=== "Docker"

    ```bash
    docker exec easydc easydc --reset-2fa alice
    ```

### Permissions

Everyone can view every page, including Replication, the Health Check and the Audit Log.
For each area, an account is set to **View** or **Edit**:

| Area | Edit allows |
|---|---|
| Users | add, edit, delete, enable or disable, reset passwords, unlock, move |
| Groups | add, edit, delete, members |
| Computers | enable or disable, delete, move |
| DNS records | add, edit, delete records |
| DNS zones | create and delete zones |
| GPOs | create, edit, delete, link to OUs |
| OUs | create, rename, delete |
| Password policies | the domain policy and per-group policies |
| Sites and subnets | sites, subnets and site links, and which site a DC is in |

**View all** and **Edit all** set every area at once. An **Admin** may change everything,
and is the only one who can manage EasyDC accounts, add, edit or remove servers, apply
the Health Check's fixes, move FSMO roles, remove a dead DC, and delegate control of OUs.

An action needs Edit on what it changes: adding users to a group needs Groups, and moving a
group or computer to another OU needs Groups or Computers. What an account may not change is
greyed out; clicking it says why. A refused change is also recorded in the audit log as
`access.refused`.

Only an admin can change the domain's most powerful accounts and groups: the built-in
Administrator and krbtgt, the admin groups (Domain Admins, Enterprise Admins, Schema Admins,
Administrators, the Operators groups and a few more), and anyone in them, directly or through
other groups. EasyDC makes changes as a domain admin, so otherwise Edit on Users or Groups
would be enough to reset an admin's password or join Domain Admins. For everyone else, the
buttons on those rows are greyed out.

When upgrading from a version without permissions, every existing account becomes an admin.

!!! note "Separate from the directory"
    Accounts and their permissions live in EasyDC's own database. EasyDC makes every change
    with the server's bind account, after checking the person's permissions, so people need
    no rights in the domain — not even domain accounts. Resetting a *domain* user's password is under
    [Users](#users).

## Audit log

The **Audit Log** in the top bar shows every action across all servers, newest first,
100 to a page. The search looks through the whole log, not just the latest entries, so
one bulk action on 2,000 users does not hide what came before it: type words from the
actor, action, target, server or error and press Enter; an entry must contain all of
them. **Failures only** shows just the changes that did not work.

Each entry records the time, the EasyDC user who acted, the action (for example
`user.reset_password`, `dns.zone_create` or `settings.account_create`), its target, the server, and **success** or
**failure**. Failures keep the error the server returned, so a rejected change can be
diagnosed after the fact.

### How long it is kept

By default the log is kept forever. To limit it, open **Settings → Audit log** and choose
how long entries stay in the log: 30 days to 2 years. This needs an admin.

Once an hour, and when you save, EasyDC rotates the log. Whole days past that time leave
the log and go into one compressed CSV file per day, such as
`audit-archive/audit-2026-11-23.csv.gz`, next to `easydc.db`. Days are in UTC. A day leaves
the log only after its file is safely written, so a full disk stops the rotation and loses
nothing. The failure is recorded in the log.

**Rotated files** sets how long those files are kept: forever, or 1 to 7 years from the
date of their entries. You can also choose not to make files, and then old entries are
deleted for good. Before saving, EasyDC says how many entries or files the change would
remove. Download a file from the same tab. Files are not searched by the Audit Log page.
