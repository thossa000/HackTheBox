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
## Operating System Structure
The root directory (also known as the boot partition) is where the operating system is installed. 

|Directory|	Function|
|:-:|:-:|
|Perflogs|	Can hold Windows performance logs but is empty by default.|
|Program Files|	On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here.|
|Program Files (x86)|	32-bit and 16-bit programs are installed here on 64-bit editions of Windows.|
|ProgramData|	This is a hidden folder that contains data that is essential for certain installed programs to run. This data is accessible by the program no matter what user is running it.|
|Users|	This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default.|
|Default|	This is the default user profile template for all created users. Whenever a new user is added to the system, their profile is based on the Default profile.|
|Public|	This folder is intended for computer users to share files and is accessible to all users by default. This folder is shared over the network by default but requires a valid network account to access.|
|AppData|	Per user application data and settings are stored in a hidden user subfolder (i.e., cliff.moore\AppData). Each of these folders contains three subfolders. The Roaming folder contains machine-independent data that should follow the user's profile, such as custom dictionaries. The Local folder is specific to the computer itself and is never synchronized across the network. LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, by a web browser set to protected or safe mode.|
|Windows|	The majority of the files required for the Windows operating system are contained here.|
|System, System32, SysWOW64|	Contains all DLLs required for the core features of Windows and the Windows API. The operating system searches these folders any time a program asks to load a DLL without specifying an absolute path.|
|WinSxS|	The Windows Component Store contains a copy of all Windows components, updates, and service packs.|

The tree utility is useful for graphically displaying the directory structure of a path or disk in the Windows CMD.

## File Systems
