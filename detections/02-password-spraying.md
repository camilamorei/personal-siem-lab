# DET-02 — Password Spraying

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE ATT&CK** | [T1110.003 — Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Data source** | `index=siem_lab sourcetype=siem_lab:auth` |
| **Window** | 15 minutes |
| **Threshold** | > 5 distinct usernames with failed logins from the same `src_ip` |

## Description

Detects a single source IP failing to authenticate against many different
accounts. Instead of many passwords against one account (DET-01), the attacker
tries one or a few common passwords against many accounts, staying below
per-account lockout limits.

## Logic

1. Keep only failed logins (`result=failure`).
2. Save each event's exact time before bucketing.
3. Group events into 15-minute buckets.
4. Count **distinct usernames** per source IP (`dc(user)`), not total failures.
5. Alert when a single IP has failed against more than 5 different accounts.

## SPL

```spl
index=siem_lab sourcetype=siem_lab:auth result=failure
| eval event_time=_time
| bin _time span=15m
| stats dc(user) AS distinct_users,
        count AS failures,
        values(user) AS users_tried,
        values(reason) AS reasons,
        min(event_time) AS first_seen,
        max(event_time) AS last_seen
        BY _time, src_ip
| where distinct_users > 5
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"),
       last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, src_ip, distinct_users, failures, users_tried, reasons
| sort -distinct_users
```

## Why these thresholds

- **Distinct users, not failures**: a sprayer generates few failures per account,
  so counting failures alone would miss it. What stands out is the *spread*.
- **> 5 accounts**: during normal testing, a single IP touched at most 2 accounts.
  A legitimate user typically fails on their own account only.
- **15 minutes**: spraying is often slower than brute force to avoid detection.

## Known false positives

- A shared workstation or kiosk where several people mistype passwords.
- Many users behind the same NAT/VPN/proxy IP.
- Internal security scans or misconfigured integrations testing multiple accounts.

## Known blind spots

- **Distributed spraying**: each account tried from a different IP.
- **Very slow spraying**: one account per hour stays below the 15-minute window.
- Sprays with ≤ 5 accounts per window.

## Response

1. Check `reasons`: many `unknown_user` suggests username enumeration;
   `invalid_password` means the attacker is hitting real accounts.
2. Check whether any of the `users_tried` later logged in successfully from this IP.
3. If confirmed malicious: block the source IP and alert the owners of the targeted real accounts.

## Lab validation

Generated with `python scripts/simulate_attack.py spray`
(source IP `127.0.0.77`, password `123456` against 7 usernames).
