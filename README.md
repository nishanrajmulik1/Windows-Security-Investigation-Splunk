# 🛡️ Security Investigation on Windows Machine using Splunk

## 📚 Overview
This project simulates real-world attacks on a Windows machine and uses **Splunk + Sysmon** to detect and respond to those attacks. It was built in **Microsoft Azure** with a 3-VM lab environment acting as a mini SOC (Security Operations Center).

> 🔧 Tools Used: Splunk, Sysmon, Hydra, PowerShell  
> 🌐 Platform: Microsoft Azure  
> 🎯 Goal: Detect and respond to RDP brute-force, PowerShell abuse, and Registry tampering.

---

## 💻 Lab Architecture

| Role        | OS / Tool            | Description                       |
|-------------|----------------------|-----------------------------------|
| 🖥️ Victim    | Windows Server 2022  | Target machine for attacks        |
| 🧠 SIEM      | Ubuntu Server        | Splunk server with Sysmon logs    |
| 🐉 Attacker  | Kali Linux           | Used to simulate attacks          |

---
[LabSetup](./screenshots/Lab%20%Setup.png)
[WIN-IP](./screenshots/Widows-IP.png)
[KALI-IP](./screenshots/KALI-IP.png)
[SIEM-IP](./screenshots/SIEM-IP.png)


## 🔐 Task 1: Investigating RDP Brute-Force Attacks

### 🎯 Objective
Detect repeated login failures and successful RDP attempts to identify brute-force attacks.

### 🧪 Attack Simulation
```bash
hydra -l administrator -P /path/to/passwords.txt rdp://<windows-ip>
```
[RDP](./screenshots/AttackRDP%20%Windows.png)

### 🔍 Splunk Query
```bash
index=sysmon_logs sourcetype=XmlWinEventLog:Sysmon
```
[RDPDetected](./screenshots/sysmonsplunkdashboard.png)
[EventDetail](./screenshots/sysmoneventdetails.png)
[ATTACKIP](./screenshots/AttackerIP.png)
[VERIFYIP](./screenshots/AttackVM-IP.png)

### 🛠️ Incident Response
```bash
# Block attacker IP
New-NetFirewallRule -DisplayName "Block RDP Brute Force" -Direction Inbound -Action Block -RemoteAddress <attacker-ip>
```
[BlockIP](./screenshots/BlockRDPAttackIP.png)
[BlockRDP](./screenshots/BlockedVerification.png)

# Reset compromised account
```bash
net user <username> <new_password>

# Set lockout policy
secpol.msc
# Configure:
#- Lockout Threshold: 5 attempts
#- Lockout Duration: 15 minutes
```

### 🖥️ Task 2: Investigating PowerShell Abuse
### 🎯 Objective
Detect malicious or unauthorized PowerShell commands such as file downloads or encoded scripts.

### 🧪 Attack Simulation
```bash
Invoke-WebRequest -Uri "https://secure.eicar.org/eicar.com.txt" -OutFile "$env:USERPROFILE\Downloads\eicar.com.txt"
```
[SimulateMalwareTestFile](./screenshots/SimulateMalwareFile.png)

## 🔍 Splunk Query
```bash
index=sysmon_logs sourcetype=XmlWinEventLog:Sysmon "*eicar*"
```
[malwaredetected](./screenshots/malwaredetected.png)
[malwaredetails](./screenshots/malwaredetecteddetails.png)

### 🛠️ Incident Response
```bash
Stop-Process -Name powershell -Force

New-NetFirewallRule -DisplayName "Block Malicious IP" -Direction Outbound -Action Block -RemoteAddress <malicious-ip>
```
[BlockedSuspiciousIP](./screenshots/Verifyinfirewall.png)

## 📢 Alert Setup
```bash
index=sysmon_logs EventCode=1 CommandLine="*Invoke-WebRequest*" OR CommandLine="*EncodedCommand*"
```


### 🧬 Task 3: Monitoring Registry Changes
### 🎯 Objective
Detect unauthorized registry changes that could be used for persistence or configuration tampering.

### 🧪 Attack Simulation
# Persistence entry
```bash
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MalwareTest" -Value "C:\malwaretest.exe"
```
[SimulateMalwareTest](./screenshots/Suspiciousregistry.png)

# Modify TCP settings
```
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 1
```
# Delete registry key
```
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MalwareSimulation"
```
### Malware Detected
[SuspiciousRegistry](./screenshots/Malwaredetected.png)
[EventDetail](./screenshots/Malwareeventdetails.png)

### 🛠️ Incident Response
# Isolate system
```
New-NetFirewallRule -DisplayName "Block All Traffic" -Direction Outbound -Action Block
```
[BlockTraffic](./screenshots/BlockedSuspicioustraffic.png)

# Remove persistence
```
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MalwareSimulation"

# Investigate referenced file
Get-ChildItem -Path "C:\malwaretest.exe"
```

### 🔧 Tools & Technologies

| Category           | Tools                                     |
|--------------------|--------------------------------------------|
| SIEM & Logs        | Splunk, Sysmon                             |
| Attack Simulation  | Hydra, PowerShell                          |
| Platform           | Microsoft Azure                            |
| Operating Systems  | Windows Server 2022, Ubuntu, Kali Linux    |
| Monitoring         | Sysmon + Windows Event Logs                |
| Incident Response  | PowerShell, Windows Firewall               |


### 🧠 Key Takeaways

- Built a mini-SOC environment from scratch using Microsoft Azure
- Gained experience in log collection, SIEM setup, and threat detection
- Developed and executed detection strategies for common attack patterns
- Learned hands-on incident response workflows using Splunk + Sysmon


### 📎 References

- [Sysmon GitHub](https://github.com/Sysinternals/Sysmon)
- [Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [Windows Firewall PowerShell Docs](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)

