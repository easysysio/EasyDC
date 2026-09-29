# Health check

The **Health Check** card on a server runs a battery of diagnostics against the domain and
reports each one as **passed**, **warning**, **failed** or **skipped**, with an explanation
and a hint for what to do about it.

It is **read-only**: every check runs over the same LDAP connection EasyDC already uses,
and nothing is written to the directory. Open the card to run it; **Re-run** at the top of
the report runs it again.

## What it checks

| Area | Check | Warns / fails when |
|---|---|---|
| **Time** | Clock skew | The DC's clock differs from EasyDC's host by **60 s** (warn) or **300 s**, the Kerberos limit (fail) |
| **Domain** | Domain controllers | Only one DC (no redundancy), or a DC with no `dNSHostName` |
| **Domain** | FSMO role holders | Any of the five roles has no owner, or points at a DC object that no longer exists |
| **Domain** | Functional levels | Domain or forest below 2008 R2 |
| **Replication** | Replication partners | A partition (domain, configuration, schema) has no inbound partner. Skipped with a single DC |
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

## What it does not cover

Some problems can only be seen from a shell on the domain controller, and are out of reach
over LDAP:

- database consistency (`samba-tool dbcheck`)
- SYSVOL contents, replication and ACLs
- `net ads testjoin` and service status

Replication is reported as **partner presence only**. For last-success times and failure
counts, run `samba-tool drs showrepl` on the DC.

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
