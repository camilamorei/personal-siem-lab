# DET-03 — Successful Login After Multiple Failures

| Field | Value |
|---|---|
| **Severity** | Critical |
| **MITRE ATT&CK** | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/) → [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Data source** | `index=siem_lab sourcetype=siem_lab:auth` |
| **Window** | 10 minutes |
| **Threshold** | ≥ 5 failures **and** ≥ 1 success, same `src_ip` + same `user`, success after the first failure |

## Description

Detects the most dangerous outcome of a brute-force attack: after repeatedly
failing, the same source IP successfully logs in to the same account. This
suggests the attacker guessed the password and the account may be compromised.

## Logic

Unlike DET-01 and DET-02, this search **cannot** start with `result=failure`:
filtering out successes would remove exactly the event we want to find.
Instead, it keeps every login and, for each `src_ip` + `user` pair, counts:

- how many attempts **failed**;
- how many attempts **succeeded**;
- whether the success happened **after** the first failure.

## SPL

```spl
index=siem_lab sourcetype=siem_lab:auth
| eval event_time=_time
| eval fail_time=if(result="failure", event_time, null()),
       success_time=if(result="success", event_time, null())
| bin _time span=10m
| stats count(fail_time) AS failures,
        count(success_time) AS successes,
        min(fail_time) AS first_failure,
        max(success_time) AS compromised_at
        BY _time, src_ip, user
| where failures >= 5 AND successes >= 1 AND compromised_at > first_failure
| eval first_failure=strftime(first_failure, "%Y-%m-%d %H:%M:%S"),
       compromised_at=strftime(compromised_at, "%Y-%m-%d %H:%M:%S")
| table first_failure, compromised_at, src_ip, user, failures, successes
```

`fail_time` and `success_time` only exist for failures and successes
respectively; `count(field)` counts only events where that field exists.

## Why these thresholds

- **≥ 5 failures**: same baseline as DET-01, so a user who mistypes once or
  twice and then logs in is not flagged.
- **Success after the first failure**: the order matters — a success followed
  by failures is a different story (e.g. someone else using a shared IP).
- **10 minutes**: enough to cover the attack plus the moment it succeeds.

## Known false positives

- A legitimate user who forgot their password, tried many variations and finally remembered it.
- An automated service retrying with an old password until it was updated.

## Known blind spots

- Attacker switches IP right before the successful attempt.
- Failures and success split across different 10-minute buckets.

## Response

**Treat as a confirmed incident until proven otherwise.**

1. Contact the account owner to confirm whether the login was theirs.
2. Reset the password and terminate the account's active sessions.
3. Block the source IP.
4. Review what the account did after `compromised_at`.

## Lab validation

Generated with `python scripts/simulate_attack.py bruteforce`
(source IP `127.0.0.66`, 10 failures against `bob`, then success with the correct password).
