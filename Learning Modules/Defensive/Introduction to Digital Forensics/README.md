# Introduction to Digital Forensics
Brief notes for the Introduction to Digital Forensics module in the HackTheBox Defensive Security learning path.

Digital forensics, often referred to as computer forensics or cyber forensics, is a specialized branch of cybersecurity that involves the collection, preservation, analysis, and presentation of digital evidence to investigate cyber incidents, criminal activities, and security breaches.

Digital forensics aims to reconstruct timelines, identify malicious activities, assess the impact of incidents, and provide evidence for legal or regulatory proceedings.

### Key Concepts:

1. Electronic Evidence: Digital forensics deals with electronic evidence, which can include files, emails, logs, databases, network traffic, and more. This evidence is collected from computers, mobile devices, servers, cloud services, and other digital sources.
2. Preservation of Evidence: Ensuring the integrity and authenticity of digital evidence is crucial. Proper procedures are followed to preserve evidence, establish a chain of custody, and prevent any unintentional alterations.
3. Types of Cases: Digital forensics is applied in a variety of cases, including:
- Cybercrime investigations (hacking, fraud, data theft).
- Intellectual property theft.
- Employee misconduct investigations.
- Data breaches and incidents affecting organizations.
- Litigation support in legal proceedings.

The basic steps for performing a forensic investigation are:

- Create a Forensic Image
- Document the System's State
- Identify and Preserve Evidence
- Analyze the Evidence
- Timeline Analysis
- Identify Indicators of Compromise (IOCs)
- Report and Documentation

## Windows Forensics Overview
### Execution Artifacts

|Artifact	|Location/Registry Key	|Data Stored|
|:-:|:-:|:-:|
|Prefetch Files |C:\Windows\Prefetch|	Metadata about executed applications (file paths, timestamps, execution count)
Shimcache|	Registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache|	Program execution details (file paths, timestamps, flags)
Amcache|	C:\Windows\AppCompat\Programs\Amcache.hve (Binary Registry Hive)|	Application details (file paths, sizes, digital signatures, timestamps)
UserAssist|	Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist|	Executed program details (application names, execution counts, timestamps)
RunMRU Lists|	Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU|	Recently executed programs and their command lines
Jump Lists|	User-specific folders (e.g., %AppData%\Microsoft\Windows\Recent)|	Recently accessed files, folders, and tasks associated with applications
Shortcut (LNK) Files|	Various locations (e.g., Desktop, Start Menu)|	Target executable, file paths, timestamps, user interactions
Recent Items|	User-specific folders (e.g., %AppData%\Microsoft\Windows\Recent)|	Recently accessed files
Windows Event Logs|	C:\Windows\System32\winevt\Logs|	Various event logs containing process creation, termination, and other events

### Windows Persistence Artifacts

Example of Autorun keys used for persistence:

1. Run/RunOnce Keys

- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\

2. Keys used by WinLogon Process

- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell

3. Startup Keys

- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User


To scrutinize scheduled tasks, we should navigate to C:\Windows\System32\Tasks and examine the XML files' content.

Malicious actors often tamper with or craft rogue services to ensure persistence and retain unauthorized access. The registry location to keep an eye on is: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services.


## Extracting Host-based Evidence & Rapid Triage
### Host-based Evidence - Acquiring Memory with WinPmem

```
# Run as admin:
C:\Users\X\Downloads> winpmem_mini_x64_rc2.exe memdump.raw
```
#### Acquiring VM Memory

Here are the steps to acquire memory from a Virtual Machine (VM).

1. Open the running VM's options
2. Suspend the running VM
3. Locate the .vmem file inside the VM's directory

This category includes artifacts such as:

- Registry
- Windows Event Log
- System-related artifacts (e.g., Prefetch, Amcache)
- Application-specific artifacts (e.g., IIS logs, Browser history)

Here are some types of data found in RAM that are valuable for incident investigation:

- Network connections
- File handles and open Files
- Open registry keys
- Running processes on the system
- Loaded modules
- Loaded device drivers
- Command history and console sessions
- Kernel data structures
- User and credential information
- Malware artifacts
- System configuration
- Process memory regions

The following outlines a systematic approach to memory forensics, formulated to aid in in-memory investigations and drawing inspiration from SANS's six-step memory forensics methodology.

1. Process Identification and Verification: Let's begin by identifying all active processes. Malicious software often masquerades as legitimate processes, sometimes with subtle name variations to avoid detection.
   
- Enumerate all running processes.
- Determine their origin within the operating system.
- Cross-reference with known legitimate processes.
- Highlight any discrepancies or suspicious naming conventions.

2. Deep Dive into Process Components: Once we've flagged potentially rogue processes, our next step is to scrutinize the associated Dynamic Link Libraries (DLLs) and handles. Malware often exploits DLLs to conceal its activities. We should:

- Examine DLLs linked to the suspicious process.
- Check for unauthorized or malicious DLLs.
- Investigate any signs of DLL injection or hijacking.

3. Network Activity Analysis: Many malware strains, especially those that operate in stages, necessitate internet connectivity. They might beacon to Command and Control (C2) servers or exfiltrate data. To uncover these:

- Review active and passive network connections in the system's memory.
- Identify and document external IP addresses and associated domains.
- Determine the nature and purpose of the communication.

4. Code Injection Detection: Advanced adversaries often employ techniques like process hollowing or utilize unmapped memory sections. To counter this, we should:

- Use memory analysis tools to detect anomalies or signs of these techniques.
- Identify any processes that seem to occupy unusual memory spaces or exhibit unexpected behaviors.

5. Rootkit Discovery: Achieving stealth and persistence is a common goal for adversaries. Rootkits, which embed deep within the OS, grant threat actors continuous, often elevated, system access while evading detection. To tackle this:

- Scan for signs of rootkit activity or deep OS alterations.
- Identify any processes or drivers operating at unusually high privileges or exhibiting stealth behaviors.

6. Extraction of Suspicious Elements: After pinpointing suspicious processes, drivers, or executables, we need to isolate them for in-depth analysis. This involves:

- Dumping the suspicious components from memory.
- Storing them securely for subsequent examination using specialized forensic tools.

### The Volatility Framework
Some commonly used modules include:

- pslist: Lists the running processes.
- cmdline: Displays process command-line arguments
- netscan: Scans for network connections and open ports.
- malfind: Scans for potentially malicious code injected into processes.
- handles: Scans for open handles
- svcscan: Lists Windows services.
- dlllist: Lists loaded DLLs (Dynamic-link Libraries) in a process.
- hivelist: Lists the registry hives in memory.
