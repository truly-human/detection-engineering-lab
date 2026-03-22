# Detection Engineering Lab

## Project Overview
Detection rules for common adversary techniques mapped to MITRE ATT&CK framework.
Built using real-world sample logs to simulate attacker behaviour.

---

## Detection 1 — Password Spray (T1110.003)

### What is this attack?
An attacker tries one password against many accounts to avoid lockouts.
Unlike brute force, spraying stays under the lockout threshold per account.

### Log Source
- Windows Security Event Log
- Sample file: `kerberos_pwd_spray_4771.evtx`

### Key Event IDs
| Event ID | Meaning |
|----------|---------|
| 4771 | Failed Kerberos pre-authentication (wrong password) |
| 4768 | Kerberos ticket requested (recon activity) |
| 1102 | Audit log cleared (post-attack cover tracks) |

### What I Found in the Logs
- 2 failed authentication attempts (Event ID 4771)
- Both from the same source IP: `172.16.66.1`
- Two accounts targeted: `Administrator` and `backdoor`
- Failure Code `0x18` confirms wrong password on both attempts
- Log clearing event (1102) observed after failed attempts

### Splunk Detection Rule (SPL)
```spl
index=windows EventCode=4771
| stats count by Client_Address, Account_Name
| where count >= 2
| table Client_Address, Account_Name, count
| sort - count
```

### Sentinel Detection Rule (KQL)
```kql
SecurityEvent
| where EventID == 4771
| where Status == "0x18"
| summarize FailedAttempts = count() by IpAddress, TargetAccount, bin(TimeGenerated, 5m)
| where FailedAttempts >= 2
| project TimeGenerated, IpAddress, TargetAccount, FailedAttempts
| sort by FailedAttempts desc
```

### Rule Validation
Logically validated against sample EVTX data. Both 4771 events share 
Client Address 172.16.66.1 with Failure Code 0x18, meeting the detection 
threshold. In production, threshold should be raised to 5-10 to reduce 
false positives.

### False Positives
- Legitimate users mistyping passwords multiple times
- Service accounts with expired credentials
- Password reset scenarios

### MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique: T1110.003 — Password Spraying

---
