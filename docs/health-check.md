# Health check

**Health** in the sidebar runs a battery of diagnostics against the domain and
reports each one as **passed**, **warning**, **failed** or **skipped**, with an explanation
and a hint for what to do about it.

It is **read-only**: every check runs over the same LDAP connection EasyDC already uses,
and nothing is written to the directory. Opening the page runs it; **Check again** at the top
runs it again. The server's Overview runs it too, and lists warnings and failures under
*Needs attention*.

## What it checks

| Area | Check | Warns / fails when |
|---|---|---|
| **Time** | Clock skew | The DC's clock differs from EasyDC's host by **60 s** (warn) or **300 s**, the Kerberos limit (fail) |
| **Domain** | Domain controllers | Only one DC (no redundancy), or a DC with no `dNSHostName` |
| **Domain** | FSMO role holders | Any of the five roles has no owner, or points at a DC object that no longer exists |
| **Domain** | Functional levels | Domain or forest below 2008 R2 |
| **Replication** | Replication partners | On every DC: a link with failed attempts or no success for a day fails, one quiet for over an hour or with automatic replication disabled warns, a DC with no inbound partners fails, and a DC EasyDC cannot reach warns. Skipped with a single DC |
| **DNS** | Service location records | A required record is missing: the `_ldap`, `_kerberos`, `_kpasswd` and `_gc` SRV records, their `_msdcs` forms, each DC's host record, or its `<GUID>._msdcs` CNAME |
| **Security** | LDAPS | Port 636 unreachable, or the certificate expires within **30 days** (warn) or has expired (fail) |
| **Security** | Password and lockout policy | No minimum length (fail), or weaker than Samba's defaults — complexity off, no lockout, no expiry, no history (warn) |
| **Security** | Machine account quota | `ms-DS-MachineAccountQuota` above 0, so any user can join machines |
| **Security** | Anonymous LDAP access | `dSHeuristics` allows anonymous operations |
| **Security** | Unconstrained delegation | An account other than a DC is trusted for unconstrained delegation |
| **Security** | Privileged groups | A disabled account is still in Domain Admins, Enterprise Admins, Schema Admins or Administrators — directly or through nested groups |
| **Hygiene** | Stale computers | Enabled computer accounts with no logon for **90 days** |
| **Hygiene** | Password flags | Accounts flagged *password not required* (fail) or *password never expires* (warn) |

DNS records are looked up by full name across all of the domain's DNS partitions, so the
check works whether `_msdcs` is part of the domain zone or a zone of its own.

## Reading the results

- **Skipped** means a check could not run, and says why — usually an attribute the bind
  account cannot read. It is not a pass.
- One check failing to run never stops the others.
- The report shows how long the run took. On a large domain it takes longer, because the
  hygiene checks read every user and computer account and the DNS check reads every record.

## Hiding a finding

Some warnings are known and accepted: a lab domain that needs no lockout, or a service account
whose password never expires on purpose. An admin can hide such a finding with **Hide…** next
to it, and choose how long:

- **Until it changes.** The finding comes back as soon as the check finds something
  different: another account in the list, a different setting, or a warning that becomes a
  failure.
- **Always.** The check stays hidden on this server whatever it finds, until someone shows it
  again.

A hidden finding is left out of the counts on the Health page and out of the problems on the
Overview. Nothing in the directory changes, and anyone can still see it under the **Hidden**
filter, with who hid it, when, and the reason if one was given. **Show again** brings it
back.

- Only warnings and failures can be hidden. A check that passes again shows as passed.
- Hiding is per server, and only admins can hide or show a finding. Both are recorded in the
  **audit log** as `health.hide` and `health.show`.

## What it does not cover

Some problems can only be seen from a shell on the domain controller, and are out of reach
over LDAP:

- database consistency (`samba-tool dbcheck`)
- SYSVOL contents, replication and ACLs
- `net ads testjoin` and service status

Directory replication is covered, on every DC — the **Replication** page has the detail.
SYSVOL replication (the Group Policy files) is not: Samba does not replicate SYSVOL itself,
so it depends on whatever you set up for it (rsync, for example).

## Fixing what it finds

Where a finding can be fixed safely, the fix is shown under it:

| Finding | Fix | Undo |
|---|---|---|
| **Stale computers** | Disable the selected computer accounts | Re-enable on the Computers page |
| **Privileged groups** | Remove a disabled account from the group that grants the rights | Add it back on the Groups page |
| **Password flags** | Require a password on accounts flagged *password not required* | Set the flag again with samba-tool |
| **Machine account quota** | Set it to 0 | Change it on the Password Policy page |

The **password policy** finding links to the Password Policy page, which is where it is
fixed.

Every fix works the same way:

- You choose which items to change, then see **exactly what will be written** before
  anything is.
- When you apply, the list is **worked out again from the directory** rather than taken
  from the page — so an item someone else has already fixed, or one that no longer
  qualifies, is left alone.
- Each change is recorded in the **audit log** under `health.fix.*`, and the result page
  shows which succeeded and why any failed.

A few rules keep the fixes safe:

- **Domain controller accounts are never offered for disabling**, even when stale.
- **Membership through nested groups** is removed from the group the account actually
  belongs to. That also ends whatever else that group grants, which the preview says.
- Membership through an account's **primary group** cannot be removed this way. It is
  reported, but no fix is offered.
- **Non-expiring passwords get no button.** They are usually service accounts, and
  expiring one without warning breaks whatever uses it.

Some findings have no button at all, because a wrong fix is hard to undo: FSMO roles,
replication, missing DNS records, delegation and anonymous access. The hint under each
says what to do.
