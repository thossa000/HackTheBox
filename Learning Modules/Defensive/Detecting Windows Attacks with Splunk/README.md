# Detecting Windows Attacks with Splunk
Brief notes for the Detecting Windows Attacks with Splunk module in HackTheBox's Defensive Security Analyst pathway.

## Detecting Common User/Domain Recon
### Domain Reconnaissance
An example of AD domain reconnaissance is when an adversary executes the net group command to obtain a list of Domain Administrators.

Common native tools/commands utilized for domain reconnaissance include:

- whoami /all
- wmic computersystem get domain
- net user /domain
- net group "Domain Admins" /domain
- arp -a
- nltest /domain_trusts

### Detecting Recon By Targeting Native Windows Executables
```
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 earliest=1690447949 latest=1690450687
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
```
### Detecting Recon By Targeting BloodHound
```
index=main earliest=1690195896 latest=1690285475 source="WinEventLog:SilkService-Log"
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```

## Detecting Password Spraying
A common pattern is multiple failed logon attempts with Event ID 4625 - Failed Logon from different user accounts but originating from the same source IP address within a short time frame.

Other event logs that may aid in password spraying detection include:

- 4768 and ErrorCode 0x6 - Kerberos Invalid Users
- 4768 and ErrorCode 0x12 - Kerberos Disabled Users
- 4776 and ErrorCode 0xC0000064 - NTLM Invalid Users
- 4776 and ErrorCode 0xC000006A - NTLM Wrong Password
- 4648 - Authenticate Using Explicit Credentials
- 4771 - Kerberos Pre-Authentication Failed

```
index=main earliest=1690280680 latest=1690289489 source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
```
