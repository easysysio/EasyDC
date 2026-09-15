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
| **Security** | Machine account quota | `ms-DS-MachineAccountQuota` above 0, so any user can join machines |
| **Security** | Anonymous LDAP access | `dSHeuristics` allows anonymous operations |
| **Security** | Unconstrained delegation | An account other than a DC is trusted for unconstrained delegation |
| **Security** | Privileged groups | A disabled account is still in Domain Admins, Enterprise Admins, Schema Admins or Administrators |
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

!!! info "Why no fix buttons"
    Remediation is deliberately not automated. Some fixes are safe, like recreating a missing
    DNS record; others, like seizing an FSMO role, can split a domain if done wrongly. The
    hints tell you what to do, and the changes are yours to make.
