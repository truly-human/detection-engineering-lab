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
---

## Detection 2 — Pass the Hash (T1550.002)

### What is this attack?
An attacker steals a password hash from memory and uses it to authenticate
to other machines without knowing the actual plaintext password.
Commonly performed using Mimikatz sekurlsa::pth command.

### Log Source
- Windows Security Event Log
- Sample file: `LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`

### Key Event IDs
| Event ID | Meaning |
|----------|---------|
| 4624 | Successful logon (with suspicious Type 9 indicator) |
| 4672 | Special privileges assigned — attacker gained admin access |
| 4688 | New process created — commands executed post-compromise |

### What I Found in the Logs
- Logon Type 9 (NewCredentials) — specific to Mimikatz PTH command
- Authentication Package: Negotiate combined with Type 9 is a known Mimikatz signature
- Logon GUID all zeros — indicates forged credentials, not a real Kerberos ticket
- Source Address `::1` (localhost) — attack executed locally after initial access
- Account `user01` in domain `EXAMPLE` was used to move laterally

### Splunk Detection Rule (SPL)
```spl
index=windows EventCode=4624 Logon_Type=9
| stats count by Account_Name, Workstation_Name, Source_Network_Address
| where count >= 1
| table Account_Name, Workstation_Name, Source_Network_Address, count
```

### Sentinel Detection Rule (KQL)
```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 9
| where AuthenticationPackageName == "Negotiate"
| where LogonGuid == "00000000-0000-0000-0000-000000000000"
| project TimeGenerated, AccountName, WorkstationName, IpAddress, LogonType
| sort by TimeGenerated desc
```

### Rule Validation
Logically validated against sample EVTX data. The 4624 event shows
Logon Type 9 with Negotiate package and zeroed GUID — three stacked
indicators that together form a high-fidelity PTH signature with very
low false positive rate.

### False Positives
- Runas /netonly command used by legitimate admins generates Type 9 logons
- Some legitimate applications use NewCredentials logon type
- Recommend whitelisting known admin workstations

### MITRE ATT&CK Mapping
- Tactic: Lateral Movement
- Technique: T1550.002 — Pass the Hash
