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
