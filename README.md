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

---

## Detection 3 — SeDebugPrivilege Abuse via Mimikatz (T1134)

### What is this attack?
An attacker enables SeDebugPrivilege on their process, which grants
the ability to read and write memory of other processes. This is a
required step before credential dumping tools like Mimikatz can steal
password hashes from memory. This detection catches that enablement.

### Log Source
- Windows Security Event Log
- Sample file: `win10_4703_SeDebugPrivilege_enabled.evtx`

### Key Event IDs
| Event ID | Meaning |
|----------|---------|
| 4703 | A token right (privilege) was adjusted on a process |

### What I Found in the Logs
- Process `mimikatz.exe` running directly from Desktop — no attempt to hide
- SeDebugPrivilege explicitly enabled by the process
- Subject and Target are the same account (`IEUser`) — self-granted privilege
- Machine: `MSEDGEWIN10` — standard workstation, not a server

### Splunk Detection Rule (SPL)
```spl
index=windows EventCode=4703 Enabled_Privileges="SeDebugPrivilege"
| where Process_Name!="C:\\Windows\\System32\\lsass.exe"
| table Account_Name, Process_Name, Host, _time
| sort - _time
```

### Sentinel Detection Rule (KQL)
```kql
SecurityEvent
| where EventID == 4703
| where EnabledPrivilegeList contains "SeDebugPrivilege"
| where ProcessName !contains "lsass.exe"
| project TimeGenerated, AccountName, ProcessName, Computer
| sort by TimeGenerated desc
```

### Rule Validation
Logically validated against sample EVTX data. Single 4703 event shows
mimikatz.exe explicitly enabling SeDebugPrivilege. The lsass.exe
exclusion removes the only common legitimate use of this privilege,
making this a high-fidelity detection with very low false positive rate.

### False Positives
- lsass.exe legitimately uses SeDebugPrivilege — excluded in rule
- Some legitimate debugging tools may enable this privilege
- Recommend whitelisting known developer machines in production

### How This Links to Detection 2
SeDebugPrivilege enablement (this detection) is the step that makes
Pass the Hash (Detection 2) possible. Together they represent two
stages of the same attack chain — privilege enablement followed by
credential theft.

### MITRE ATT&CK Mapping
- Tactic: Privilege Escalation
- Technique: T1134 — Access Token Manipulation
