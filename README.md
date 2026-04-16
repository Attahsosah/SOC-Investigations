# 🛡️ SIEM Home Lab — Splunk Threat Detection

## Overview
This project documents the build-out of a fully functional SIEM home lab 
using Splunk Enterprise. The lab simulates a real SOC environment where 
attacks are executed, logged, detected, and alerted on. The goal was to 
demonstrate practical skills in log ingestion, threat detection, SPL query 
writing, and dashboard building — core competencies for a SOC Analyst role.

---

## 🖥️ Lab Architecture
[Kali Linux VM] ──attack──▶ [Ubuntu Server VM] ──logs──▶ [Splunk Enterprise]
192.168.0.117                 192.168.0.113              192.168.0.103:8000
(Attacker)                    (Target/Log Source)         (Windows Host)

### Environment
| Component | Details |
|---|---|
| Host Machine | Windows Laptop, 16GB RAM |
| SIEM | Splunk Enterprise 10.2.2 |
| Target Machine | Ubuntu Server VM — 192.168.0.113 |
| Attacker Machine | Kali Linux VM — 192.168.0.117 |
| Virtualization | Oracle VirtualBox |

---

## 🛠️ Tools Used
- **Splunk Enterprise 10.2.2** — SIEM platform for log ingestion and detection
- **Splunk Universal Forwarder 10.2.2** — Log shipping agent on Ubuntu VM
- **Hydra** — SSH brute force tool used to simulate credential attacks
- **Nmap** — Network scanner used for reconnaissance simulation
- **Oracle VirtualBox** — Hypervisor for running Ubuntu and Kali VMs
- **Kali Linux** — Attacker machine
- **Ubuntu Server 22.04** — Target/log source machine

---

## ⚙️ Setup & Configuration

### Step 1 — Ubuntu Server VM
- Created Ubuntu Server VM in VirtualBox (4GB RAM, 2 CPUs, 20GB disk)
- Configured network adapter as **Bridged Adapter** to enable host-VM 
  communication
- Confirmed connectivity from Windows host via ping to `192.168.0.113`

### Step 2 — Splunk Enterprise Installation
- Installed Splunk Enterprise 10.2.2 on Windows host machine
- Accessible at `http://localhost:8000`
- Configured receiving port **9997** for incoming Universal Forwarder logs
- Added Windows Firewall inbound rule to allow TCP traffic on port 9997

### Step 3 — Universal Forwarder Setup
- Installed Splunk Universal Forwarder 10.2.2 (amd64) on Ubuntu VM
- Pointed forwarder to Splunk indexer at `192.168.0.103:9997`
- Configured forwarder to monitor:
  - `/var/log/auth.log` — authentication events
  - `/var/log/syslog` — general system events
- Confirmed forwarder status: **Active**

### Step 4 — Log Ingestion Verified
- Ran `index=main` search in Splunk Search & Reporting
- Confirmed two sourcetypes arriving from Ubuntu VM:
  - `auth` — from `/var/log/auth.log`
  - `syslog` — from `/var/log/syslog`

---

## 🔴 Attacks Simulated

### 1. SSH Brute Force Attack
**Tool:** Hydra  
**Command:**
```bash
hydra -l siem -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.113 -t 4 -V
```
**What it does:** Attempts hundreds of SSH login combinations against the 
target using the rockyou.txt wordlist, simulating a real credential 
stuffing attack.  
**Result:** 413 failed login attempts logged in Splunk from `192.168.0.117`

---

### 2. Nmap Reconnaissance Scan
**Tool:** Nmap  
**Command:**
```bash
nmap -sS -A 192.168.0.113
```
**What it does:** Performs a SYN stealth scan to identify open ports, 
running services, and OS fingerprint without completing a full TCP 
handshake — making it harder to detect.  
**Result:** Port 22/tcp identified as open, running OpenSSH 8.9p1 on 
Linux 4.X/5.X

---

### 3. Privilege Escalation Attempts
**Method:** Manual failed sudo and su commands on Ubuntu VM  
**What it does:** Simulates an insider threat or compromised user 
attempting to escalate privileges on a system.  
**Result:** 76 authentication failure events logged for user `siem`

---

## 🔍 Detection Rules Built

### Rule 1 — SSH Brute Force Detection
**SPL Query:**
index=main "Failed password"
| rex "from (?P<src_ip>\d+.\d+.\d+.\d+)"
| stats count by src_ip
| where count > 5
**Logic:** Extracts source IP from raw auth.log events and flags any IP 
with more than 5 failed login attempts.  
**Alert:** SSH Brute Force Detected | Severity: High | Type: Real-time

---

### Rule 2 — Privilege Escalation Detection
**SPL Query:**
index=main "authentication failure"
| rex "user=(?P<username>\w+)"
| stats count by username
| where count > 3
**Logic:** Extracts username from authentication failure events and flags 
any user exceeding 3 failures — consistent with repeated sudo/su attempts.  
**Alert:** Privilege Escalation Attempt Detected | Severity: Medium | 
Type: Real-time

---

### Rule 3 — Login Activity Timeline
**SPL Query:**
index=main ("Failed password" OR "Accepted password")
| rex "(?P<action>Failed|Accepted) password"
| timechart count by action
**Logic:** Tracks failed vs successful login attempts over time to identify 
sustained attack patterns and anomalies.  
**Alert:** Abnormal Login Activity Timeline | Severity: Medium | 
Type: Real-time

---

## 📊 Dashboard — SOC Home Lab Threat Detection

Built a 4-panel Splunk dashboard to visualize attack activity in real time:

| Panel | Visualization | Purpose |
|---|---|---|
| Top Attacker IPs | Bar Chart | Shows source IPs with highest failed login attempts |
| Login Activity Timeline | Line Chart | Tracks failed vs successful logins over time |
| Failed Authentication by User | Table | Shows users with most authentication failures |
| Recent High Severity Events | Table | Top 10 most active attacker IPs across all attack types |

---

## 🔑 Key Findings

| Finding | Detail |
|---|---|
| Attacker IP | 192.168.0.117 (Kali VM) |
| Target IP | 192.168.0.113 (Ubuntu VM) |
| Attack Vector | SSH (Port 22) |
| Total Failed Logins | 413 events |
| Auth Failures (Priv Esc) | 76 events |
| Open Port Discovered | 22/tcp — OpenSSH 8.9p1 |
| Detection Time | Real-time via Splunk alerts |

---

## 📖 Lessons Learned
- Splunk's `rex` command is essential for extracting fields from 
  unstructured log data that hasn't been automatically parsed
- Bridged networking in VirtualBox is critical for realistic host-to-VM 
  attack simulation
- A single Hydra brute force session generates hundreds of log events 
  very quickly — highlighting the importance of threshold-based alerting 
  rather than alerting on every single event
- Real SOC environments would complement these detections with GeoIP 
  lookups, threat intelligence feed correlation, and automated SOAR 
  playbooks for response

---

## 🚀 Next Steps
- Integrate threat intelligence feeds (AbuseIPDB, AlienVault OTX) to 
  enrich detected IPs
- Add GeoIP lookup to identify geographic origin of attack traffic
- Simulate additional attack types (lateral movement, data exfiltration)
- Pursue Splunk Core Certified User certification to formalize SIEM skills

---

## 📁 Screenshots
All screenshots are available in the `/screenshots` folder of this repository.
