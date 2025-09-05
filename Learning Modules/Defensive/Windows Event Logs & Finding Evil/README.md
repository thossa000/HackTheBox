# Windows Event Logs & Finding Evil
Brief notes on the HackTheBox Academy module, Windows Event Logs & Finding Evil, under the SOC Analyst learning path.

## Windows Event Logging Basics
The logs are categorized into different event logs, such as "Application", "System", "Security", and others, to organize events based on their source or purpose.

Event logs can be accessed using the Event Viewer application or programmatically using APIs such as the Windows Event Log API.

Accessing the Windows Event Viewer as an administrative user allows us to explore the various logs available.

The default Windows event logs consist of Application, Security, Setup, System, and Forwarded Events. The "Forwarded Events" section is unique, showcasing event log data forwarded from other machines. This central logging feature proves valuable for system administrators who desire a consolidated view.

### The Anatomy of an Event Log
When examining Application logs, we encounter two distinct levels of events: information and error.

Information events provide general usage details about the application, such as its start or stop events. Conversely, error events highlight specific errors and often offer detailed insights into the encountered issues.

Each entry in the Windows Event Log is an "Event" and contains the following primary components:

- Log Name: The name of the event log (e.g., Application, System, Security, etc.).
- Source: The software that logged the event.
- Event ID: A unique identifier for the event.
- Task Category: This often contains a value or name that can help us understand the purpose or use of the event.
- Level: The severity of the event (Information, Warning, Error, Critical, and Verbose).
- Keywords: Keywords are flags that allow us to categorize events in ways beyond the other classification options. These are generally broad categories, such as "Audit Success" or "Audit Failure" in the Security log.
- User: The user account that was logged on when the event occurred.
- OpCode: This field can identify the specific operation that the event reports.
- Logged: The date and time when the event was logged.
- Computer: The name of the computer where the event occurred.
- XML Data: All the above information is also included in an XML format along with additional event data.

The Keywords field is particularly useful when filtering event logs for specific types of events. It can significantly enhance search queries by allowing us to specify events of interest.

### Leveraging Custom XML Queries
To streamline analysis, we can create custom XML queries to identify related events using the "Logon ID" as a starting point. By navigating to "Filter Current Log" -> "XML" -> "Edit Query Manually," we gain access to a custom XML query language that enables more granular log searches.

## Sysmon Basics
System Monitor (Sysmon) is a Windows system service and device driver that remains resident across system reboots to monitor and log system activity to the Windows event log. Sysmon provides detailed information about process creation, network connections, changes to file creation time, and more.

Sysmon's primary components include:

- A Windows service for monitoring system activity.
- A device driver that assists in capturing the system activity data.
- An event log to display captured activity data.

Sysmon's unique capability lies in its ability to log information that typically doesn't appear in the Security Event logs, and this makes it a powerful tool for deep system monitoring and cybersecurity forensic analysis.

Sysmon categorizes different types of system activity using event IDs, for example, Event ID 1 corresponds to "Process Creation" events, and Event ID 3 refers to "Network Connection" events.

### Detecting DLL Hijacking
To detect a DLL hijack, we need to focus on Event Type 7, which corresponds to module load events. To achieve this, we need to modify the sysmonconfig-export.xml Sysmon configuration file we downloaded from https://github.com/SwiftOnSecurity/sysmon-config.

To utilize the updated Sysmon configuration, execute the following.
```
C:\Tools\Sysmon> sysmon.exe -c sysmonconfig-export.xml
```
With the modified Sysmon configuration, we can start observing image load events. To view these events, navigate to the Event Viewer and access "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon."

For the purpose of our detection, we will focus on a specific hijack involving the vulnerable executable calc.exe and a list of DLLs that can be hijacked.
<img width="1000" height="550" alt="image" src="https://github.com/user-attachments/assets/35335705-abf1-4048-8eff-94c32f5819a8" />

### Detecting Credential Dumping
Another critical aspect of cybersecurity is detecting credential dumping activities. One widely used tool for credential dumping is Mimikatz, offering various methods for extracting Windows credentials. One specific command, "sekurlsa::logonpasswords", enables the dumping of password hashes or plaintext passwords by accessing the Local Security Authority Subsystem Service (LSASS). LSASS is responsible for managing user credentials and is a primary target for credential-dumping tools like Mimikatz.

```
C:\Tools\Mimikatz> mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1128191 (00000000:001136ff)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : DESKTOP-NU10MTO
Logon Server      : DESKTOP-NU10MTO
Logon Time        : 5/31/2023 4:14:41 PM
SID               : S-1-5-21-2712802632-2324259492-1677155984-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * NTLM     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
         * SHA1     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX0812156b
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        ssp :   KO
        credman :
```
To detect this activity, we can rely on a different Sysmon event. Instead of focusing on DLL loads, we shift our attention to process access events. By checking Sysmon event ID 10, which represents "ProcessAccess" events, we can identify any suspicious attempts to access LSASS.

## Event Tracing for Windows (ETW)
