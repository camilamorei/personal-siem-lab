# DET-01 — Brute Force Against a Single Account

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE ATT&CK** | [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| **Data source** | `index=siem_lab sourcetype=siem_lab:auth` |
| **Window** | 5 minutes |
| **Threshold** | ≥ 5 failed logins, same `src_ip` + same `user` |

## Description

Detects a single source IP repeatedly failing to authenticate against the same
account in a short time window — the classic pattern of an attacker guessing
passwords for a known, existing user.

## Logic

1. Keep only failed logins (`result=failure`).
2. Group events into 5-minute buckets (`bin _time span=5m`).
3. Count failures per bucket, per source IP, per user.
4. Alert when the count reaches the threshold.

## SPL

```spl
index=siem_lab sourcetype=siem_lab:auth result=failure
| bin _time span=5m
| stats count AS failures,
        min(_time) AS first_seen,
        max(_time) AS last_seen,
        values(reason) AS reasons
        BY _time, src_ip, user
| where failures >= 5
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"),
       last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, src_ip, user, failures, reasons
| sort -failures
```

## Why these thresholds

- **5 failures**: a legitimate user rarely mistypes a password more than 2–3
  times in a row before resetting it.
- **5 minutes**: wide enough to catch attacks slightly slower than a burst,
  short enough to keep the signal focused.

## Known false positives

- A user who forgot their password and keeps trying variations.
- A service or script configured with an outdated password, retrying automatically.
- Many users behind the same NAT/proxy IP (less relevant in this lab).

## Known blind spots

- **Low-and-slow attacks**: fewer than 5 attempts per 5 minutes never trigger.
- **Distributed attacks**: many IPs, each below the threshold.
- **Password spraying**: one attempt per account — covered by DET-02.

## Response

1. Check whether any **success** followed the failures from the same IP (possible compromise — see DET-03).
2. Review the `user_agent` (browser vs. script).
3. If confirmed malicious: block the source IP and reset the targeted account's password.

## Lab validation

Generated with `python scripts/simulate_attack.py bruteforce`
(source IP `127.0.0.66`, target `bob`, 10 failures in under 1 minute).
