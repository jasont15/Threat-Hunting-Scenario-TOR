# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jasont15/Threat-Hunting-Scenario-TOR/blob/main/Threat-Hunting-Scenario-TOR-Event-Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered that the user “enterpriseuser1” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and to the creation of a file called “tor-shopping-list.txt”. These events began at Jun 1, 2026 10:28:02 AM.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "practice-lab-jt"
| where InitiatingProcessAccountName == "enterpriseuser1"
| where FileName contains "tor"
| where Timestamp >= datetime(Jun 1, 2026 10:28:02 AM)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1776" height="490" alt="image" src="https://github.com/user-attachments/assets/a229665f-58bd-4cda-a3bb-1000efbe37b1" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for ProcessCommandLine logs that contain "tor-browser-windows-x86_64-portable-15.0.14.exe". Based on that query, we found that on Jun 1, 2026 10:31:57 AM, user enterpriseuser1 ran the Tor Browser executable from their Downloads folder on the computer practice-lab-jt, using a command for silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "practice-lab-jt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.14.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="886" height="69" alt="image" src="https://github.com/user-attachments/assets/185be4e1-17a8-46b0-95a8-e2fd7bb1f737" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched in the DeviceProcessEvents table for any indicators that enterpriseuser1 actually opened the browser. The logs show that they did open it on Jun 1, 2026 10:32:21 AM. From that time on, other instances of firefox.exe (Tor) as well as tor.exe were spawned.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "practice-lab-jt"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="889" height="240" alt="image" src="https://github.com/user-attachments/assets/9a49a072-7b7d-47f5-828f-a18cdeb1037b" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indicators that the tor browser was used to establish a connection using any of its common ports. On Jun 1, 2026 10:33:01 AM, the device practice-lab-jt recorded a successful outbound connection initiated by the user enterpriseuser1 to the remote IP address 178.254.20.235 on port 9001. The connection was made by tor.exe from the Tor Browser installation path, indicating this activity is associated with Tor network usage. There were also a couple of connections over 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents 
| where DeviceName == "practice-lab-jt" 
| where InitiatingProcessAccountName != "system" 
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe") 
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443") 
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath 
| order by Timestamp desc
```
<img width="887" height="200" alt="image" src="https://github.com/user-attachments/assets/8660ac34-55bf-439a-9c69-1d357f73b3e8" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `Jun 1, 10:28:02 AM`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `Jun 1, 10:31:57 AM`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `Jun 1, 10:32:21 AM`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `Jun 1, 10:33:01 AM`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. File Creation - TOR Shopping List

- **Timestamp:** `Jun 1, 10:43:55 AM`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "enterpriseuser1" on the "pratice-lab-jt" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `practice-lab-jt` by the user `enterpriseuser1`. The device was isolated, and the user's direct manager was notified.

---
