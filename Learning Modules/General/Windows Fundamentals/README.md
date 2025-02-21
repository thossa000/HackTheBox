# Windows Fundamentals
Brief notes written to review the material in the HackTheBox Academy module, Windows Fundamentals.

## Windows Versions
The following is a list of the major Windows operating systems and associated version numbers:

|Operating System Names|	Version Number|
|:-:|:-:|
|Windows NT 4	|4.0|
|Windows 2000	|5.0|
|Windows XP	|5.1|
|Windows Server 2003, 2003 R2	|5.2|
|Windows Vista, Server 2008	|6.0|
|Windows 7, Server 2008 R2	|6.1|
|Windows 8, Server 2012	|6.2|
|Windows 8.1, Server 2012 R2	|6.3|
|Windows 10, Server 2016, Server 2019	|10.0|

We can use the Get-WmiObject cmdlet to find information about the operating system. This cmdlet can be used to get instances of WMI classes or information about available WMI classes. There are a variety of ways to find the version and build number of our system. We can easily obtain this information using the win32_OperatingSystem class.

```
PS C:\htb> Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber

Version    BuildNumber
-------    -----------
10.0.19041 19041
```

Other useful classes include:

- Win32_Process - to get a process listing
- Win32_Service - to get a listing of services
- Win32_Bios - to get Basic Input/Output System (BIOS) information
- ComputerName - to get information about remote computers

## Remote Access Concepts
Local access is the most common way to access any computer, including computers running Windows. Remote Access is accessing a computer over a network. Local access to a computer is needed before one can access another computer remotely. Some of the most common remote access technologies include but aren't limited to:

- Virtual Private Networks (VPN)
- Secure Shell (SSH)
- File Transfer Protocol (FTP)
- Virtual Network Computing (VNC)
- Windows Remote Management (or PowerShell Remoting) (WinRM)
- Remote Desktop Protocol (RDP)

## RDP
RDP uses a client/server architecture where a client-side application is used to specify a computer's target IP address or hostname over a network where RDP access is enabled. The target computer where RDP remote access is enabled is considered the server. Windows computers come with a builtin client application, Remote Desktop Connection (mstsc.exe).

By default, RDP listens on port 3389.

### Using xfreerdp

From a Linux-based host we can use a tool called xfreerdp to remotely access Windows targets. Here is a example command to connect to a host using xfreerdp:
```
[!bash!]$ xfreerdp /v:<targetIp> /u:htb-student /p:Password
```
