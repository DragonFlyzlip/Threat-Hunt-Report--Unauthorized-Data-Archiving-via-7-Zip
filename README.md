![image](https://github.com/user-attachments/assets/d839e9ee-9071-4296-b243-1317cab1b90d)


# Threat-Hunt-Report--Unauthorized-Data-Archiving-via-7-Zip

---

## Scenario Creation

### Platforms and Languages Leveraged
- **Platform:** Windows 10 Virtual Machine (Microsoft Azure)  
- **EDR Platform:** Microsoft Defender for Endpoint  
- **Language:** Kusto Query Language (KQL)  
- **Tools Observed:** PowerShell, 7-Zip

---

## Scenario

Unusual `.zip` file activity was detected on a device named `ash-threathunt`, triggering a deeper investigation. Management suspected that sensitive files might be getting archived and staged for exfiltration. A threat hunt was conducted to uncover the nature of these `.zip` activities and identify whether unauthorized software (e.g., 7-Zip) was being used to compress and store sensitive employee data. The goal was to determine whether this behavior was malicious and to isolate the machine if data staging was confirmed.

---

## High-Level IoC Discovery Plan
1. Search for `.zip` file creation and movement activity.
2. Correlate timestamps with process execution to identify the tool used.
3. Investigate if PowerShell was used for silent installation of archiving software.
4. Analyze network activity to detect signs of exfiltration or remote access.

---

## Steps Taken

### 1. Searched the DeviceFileEvents Table
Identified heavy `.zip` file creation activity on the device `ash-threathunt`.

**Query Used:**
```kusto
DeviceFileEvents
| where DeviceName contains "Ash"
| where FileName endswith ".zip"
| order by Timestamp desc 
```

**Finding:**  
Dozens of `.zip` files were created and moved into a “backup” folder by user `employee`.

---

![image](https://github.com/user-attachments/assets/6ee97428-e187-4dc8-923c-a6e4f3d4e185)


### 2. Correlated with DeviceProcessEvents Table  
Reviewed process execution around a selected zip file creation event (`2025-04-10T23:03:10.8500709Z`).

**Query Used:**
```kusto
let VMName = "ash-threathunt";
let specificTime = datetime(2025-04-10T23:03:10.8500709Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| where AccountName == "employee"
| order by Timestamp desc
```

**Finding:**  
PowerShell was used to silently install **7-Zip**, which was then used to archive employee data.

---
![image](https://github.com/user-attachments/assets/c5b3c3c5-1559-477b-8324-0cd856653232)

### 3. Searched DeviceNetworkEvents Table  
Searched for any signs of data exfiltration or suspicious network behavior during or after the 7-Zip activity.

**Finding:**  
No malicious or unusual outbound connections were detected around the event timeframe.

---

## Chronological Events

### Data Archiving Initiated
- **Timestamp:** 2025-04-10T23:03:10.850Z  
- **Event:** `.zip` files created and archived into a backup folder.
- **Action:** File archiving activity detected.

### Silent Tool Installation
- **Timestamp:** 2025-04-10T23:02:00Z (approx.)
- **Event:** PowerShell executed a silent install of 7-Zip.
- **Action:** Process execution detected.
- **Command:** PowerShell script executed with silent install parameters.
- **Process:** 7z.exe (installed and launched)

### No Exfiltration Evidence Found
- **Timestamp Range:** +/- 5 minutes around archiving
- **Finding:** No relevant network traffic (TOR, FTP, external IPs) indicating exfiltration.
- **Action:** Network review showed no indicators of external data transfer.

---

## Mapped MITRE ATT&CK Techniques

| **Tactic**         | **Technique**                                  | **ID**          | **Notes** |
|--------------------|------------------------------------------------|------------------|-----------|
| **Collection**     | Archive Collected Data via Utility             | T1560.001        | Use of 7-Zip to collect and compress sensitive data. |
| **Execution**      | PowerShell                                     | T1059.001        | PowerShell used for silent tool installation. |
| **Defense Evasion**| Signed Binary Proxy Execution                  | T1218 / T1218.011| Trusted binaries used to evade detection during execution. |
| **Impact** *(Optional)*| Data Staging Prior to Exfiltration         | T1074            | Archived data stored in a backup folder, indicating staging behavior. |

---

## Response Taken

- **Action:** Device `ash-threathunt` was **immediately isolated**.
- **Alerting:** A custom **alert rule** was created to monitor `.zip` file activity.
  - If a user exceeds a threshold (e.g., >50 `.zip` files in a short window), the system will auto-isolate the endpoint.

---

## Recommendations for Prevention & Detection

### 1. Prevent Silent Tool Installation
- **Issue:** PowerShell was used to install 7-Zip without user prompts.
- **Recommendations:**
  - Enforce **AppLocker** or **WDAC** to block unsigned tools.
  - Configure **EDR policies** to detect/block silent installs via PowerShell.

### 2. Behavior-Based Archive Monitoring
- **Issue:** Legitimate archiving tools were used for potential misuse.
- **Recommendations:**
  - Monitor for:
    - Frequent `.zip` file creation.
    - Execution of tools like `7z.exe` from user directories.
    - Archiving actions in sensitive folders (e.g., HR, Finance).
  - Implement thresholds and anomaly detection logic.
