# 🕵️‍♂️ Unhide (Delphi Port)  
### **Find hidden processes and hidden TCP/UDP ports concealed by rootkits, LKMs, or stealth techniques**  
![Delphi](https://img.shields.io/badge/Delphi-7-red?logo=delphi)

**Original C author:** *Yago Jesús*  
**Delphi 7 port & enhancements:** *Hs32-Idir*

---

## 🔍 Overview

This project is a **full Delphi 7 port** of the original C-based forensic tool by **Yago Jesús** from *unhide-forensics.info*.  
Its primary purpose is to detect:

- **hidden processes**  
- **hidden TCP/UDP ports**  
- inconsistencies caused by **kernel rootkits**, **Loadable Kernel Modules (LKMs)**, or **stealth hooking techniques**

The Delphi version preserves the original logic while adding practical improvements for modern forensic investigation.

---

## ✨ Improvements in the Delphi Version

In addition to the direct translation, this port adds:

### ✔ Retrieval of **process name**
Using:
```delphi
GetModuleBaseNameA (psapi.dll)
### ✔ Retrieval of the full executable path

Using:

QueryFullProcessImageNameA (kernel32.dll)


These enhancements allow more accurate identification of suspicious or hidden processes.

## 📂 Project Structure

/Unhide
 ├── unhide.dpr         // Main entry point
 ├── UnhideProc.pas     // Hidden process detection
 └── UnhideTCP.pas      // Hidden TCP/UDP port detection

## 🧵 Hidden Process Detection (UnhideProc.pas)

The tool uses multiple cross-validation techniques:

# 1️⃣ Toolhelp Snapshot Enumeration

Uses:

CreateToolhelp32Snapshot

Process32First / Process32Next

Lists all processes known to Windows userland.

# 2️⃣ WMIC Cross-Check

Command executed:

wmic process get ProcessId

If a PID appears in Toolhelp but not in WMIC output → it may be hidden.

# 3️⃣ OpenProcess() PID Scanning

Scans all PIDs (1 → MAX_PID = 1,000,000) and attempts:

OpenProcess(PROCESS_ALL_ACCESS, False, pid)

If a PID responds to kernel calls but is absent in WMIC:

# ➡️ Hidden Process Detected

## 🌐 Hidden TCP/UDP Port Detection (UnhideTCP.pas)

Two complementary techniques:

### ✔ 1. Query official port tables

Using:

GetExtendedTcpTable

GetExtendedUdpTable

Includes port → PID mapping.

### ✔ 2. bind() scanning (active probe)

Attempts to bind() to every port (1 → 65535).

If:

bind() fails

AND port does not appear in the official TCP/UDP tables

# ➡️ Hidden TCP/UDP Port Detected

## 🧪 Example Output
Hidden process:

Found HIDDEN PID: 1248, Process Name: C:\Windows\System32\svchost.exe

Hidden TCP port:

Found Hidden port 445

## ⚠️ Notes & Limitations

64-bit processes may appear as “inaccessible” when running from 32-bit Delphi
bind() scanning is slow by nature (full port sweep)
Administrator rights recommended
Some security software may block WMIC or snapshot scans

## 👤 Authors

Original C project: Yago Jesús
Delphi 7 port + process name/fullpath enhancements: Hs32-Idir
