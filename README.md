# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ChuckMc86/threat-hunting-scenario-tor/blob/main/threat-hunting-senario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileEvents table for ANY files that have the string "tor" in it and discovered what looks like the user "mylabs2025" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called
"tor-shopping-list.txt" on the desktop. These events began at: 2026-01-28T02:29:45.957445Z
**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "chucks-remote-v"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "mylabs2025"
| where Timestamp >= datetime(2026-01-28T02:29:45.957445Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="3986" height="428" alt="image" src="https://github.com/user-attachments/assets/8cbd0f51-0da4-46fb-b58e-4d73b795593b" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any processes containing the file (tor-browser-windows-x86_64-portable-15.0.4 (1).exe") that may have been created and found none. This may be an indication of a search but the individual may have not found what they are looking for or did not startup any applications within the browser.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "chucks-remote-v"
| where InitiatingProcessAccountName == "mylabs2025"
| where ProcessCommandLine has "tor-browser-windows-x86_64-portable-15.0.4 (1).exe"
| where Timestamp >= datetime(2026-01-28T02:29:45.957445Z)
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
No Process Was Detected.

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "chucks-remote-v" actually opened the TOR browser. There was evidence that they did open it at `2026-01-27T18:43:43Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "chucks-remote-v"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="3358" height="474" alt="image" src="https://github.com/user-attachments/assets/ecf62976-0ac1-4559-bfcd-66e08d66faca" />
---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table and although the InitiatingProcessFileName is (firefox.exe) which is a commonly used browser, the remote port used is 9150 which is used when surfing the Dark Web or using Tor.Query used to locate events: The log shows that the user account “ mylabs2025” successfully ran the Tor Browser on the computer (chucks-remote-v). The Tor Browser’s Firefox process connected to a local service on the same machine (127.0.0.1) using port 9150, which is the Tor network’s proxy port at 2026-02-11T18:23:43.7186866Z

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "chucks-remote-v"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath

```
<img width="3358" height="474" alt="image" src="https://github.com/user-attachments/assets/0ac6bf02-06f8-4d7d-a1a6-811eab394016" />

---

## Chronological Event Timeline 

# Tor Browser Activity Incident Report

**Device:** chucks-remote-v
**User Account:** mylabs2025
**Report Date:** Feb 16, 2026

---

## Executive Summary

An investigation into endpoint logs identified the download, installation, and multiple executions of the Tor Browser. Evidence confirms that the application was intentionally used to connect to the Tor network and that user-created files related to Tor activity exist on the system.

This activity occurred on **Jan 27–28, 2026** and again on **Feb 11, 2026**.

---

## Scope of Review

This report includes only events directly related to Tor Browser activity, including:

* File creation and installation artifacts
* Process execution
* Network connections
* User-created files tied to Tor usage

---

## Detailed Timeline of Events

### 1) Tor Browser Download & Installation

**Jan 27, 2026 – 6:29 PM**

* File renamed:
  `tor-browser-windows-x86_64-portable-15.0.4 (1).exe`
  Location: Downloads folder
  **Significance:** Tor installer was downloaded and prepared for execution.

**Jan 27, 2026 – 6:40 PM**

* File created:
  `Desktop\Tor Browser\Browser\tor.exe`
  **Significance:** Tor Browser extracted/installed to Desktop.

**Jan 27, 2026 – 6:40 PM**

* File created:
  `Tor Browser.lnk` (desktop shortcut)
  **Significance:** Installation completed successfully.

---

### 2) First Tor Execution & Network Use

**Jan 27, 2026 – 6:43 PM**

* Processes started:

  * `firefox.exe` (Tor Browser)
  * Tor background processes

**Jan 27, 2026 – 6:43 PM**

* Network connection from `tor.exe`

  * Remote IP: **192.42.116.201**
  * Port: **9001**
  * URL accessed:
    `https://www.moexdq5czrfhsdh52nltwymzo.com`

**Significance:**
This confirms successful connection to the Tor network and access to a Tor (.onion) site.

**Jan 27, 2026 – 6:43–6:56 PM**

* Multiple local proxy connections to **127.0.0.1:9150**
  **Significance:** Tor proxy service was actively routing browser traffic.

---

### 3) Tor-Related User File Created

**Jan 28, 2026 – 8:18 PM**

* File created:
  `tor-shopping-list.txt` (Desktop)
* Shortcut created in AppData.

**Significance:**
This indicates user interaction and file creation during Tor usage.

---

### 4) Additional Tor Usage Session

**Feb 11, 2026 – 9:40 AM – 12:36 PM**

* Processes executed:

  * `tor.exe`
  * `firefox.exe` (Tor Browser)
* Multiple connections to **127.0.0.1:9150**

**Significance:**
Tor Browser was launched and actively used again.

---

## Files Created Related to Tor Activity

### Installation & Application Artifacts

* Tor Browser installer (downloaded & renamed)
* `tor.exe` (created during extraction)
* Tor Browser desktop shortcut

### User Artifact

* **tor-shopping-list.txt**

This confirms hands-on user activity, not passive or background execution.

---

## Assessment & Conclusion

Evidence confirms that Tor Browser was:

* Downloaded and installed intentionally
* Successfully executed
* Used to connect to the Tor network
* Used across multiple sessions
* Used during creation of a user document

This activity strongly indicates **intentional Tor usage on the endpoint**.

---

## Recommended Next Steps (Optional)

* Verify whether Tor usage violates organizational policy
* Interview the user to determine business justification
* Consider endpoint monitoring or application control policies if needed

