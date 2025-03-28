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
There are 5 types of Windows file systems: FAT12, FAT16, FAT32, NTFS, and exFAT. FAT12 and FAT16 are no longer used on modern Windows operating systems. FAT32 (File Allocation Table) is widely used across many types of storage devices such as USB memory sticks and SD cards. The "32" in the name refers to the fact that FAT32 uses 32 bits of data for identifying data clusters on a storage device.

Pros of FAT32:

- Device compatibility - it can be used on computers, digital cameras, gaming consoles, smartphones, tablets, and more.
- Operating system cross-compatibility - It works on all Windows operating systems starting from Windows 95 and is also supported by MacOS and Linux.

Cons of FAT32:

- Can only be used with files that are less than 4GB.
- No built-in data protection or file compression features.
- Must use third-party tools for file encryption.

NTFS (New Technology File System) is the default Windows file system since Windows NT 3.1. In addition to making up for the shortcomings of FAT32, NTFS also has better support for metadata and better performance due to improved data structuring.\

Pros of NTFS:

- NTFS is reliable and can restore the consistency of the file system in the event of a system failure or power loss.
- Provides security by allowing us to set granular permissions on both files and folders.
- Supports very large-sized partitions.
- Has journaling built-in, meaning that file modifications (addition, modification, deletion) are logged.

Cons of NTFS:

- Most mobile devices do not support NTFS natively.
- Older media devices such as TVs and digital cameras do not offer support for NTFS storage devices.

The NTFS file system has many basic and advanced permissions. Some of the key permission types are:

|Permission Type|	Description|
|:-:|:-:|
|Full Control|	Allows reading, writing, changing, deleting of files/folders.|
|Modify|	Allows reading, writing, and deleting of files/folders.|
|List Folder Contents|	Allows for viewing and listing folders and subfolders as well as executing files. Folders only inherit this permission.|
|Read and Execute|	Allows for viewing and listing files and subfolders as well as executing files. Files and folders inherit this permission.|
|Write|	Allows for adding files to folders and subfolders and writing to a file.|
|Read|	Allows for viewing and listing of folders and subfolders and viewing a file's contents.|
|Traverse Folder|	This allows or denies the ability to move through folders to reach other files or folders. For example, a user may not have permission to list the directory contents or view files in the documents or web apps directory but with Traverse Folder permissions applied, they can access the backup archive.|
|Special Permissions|	A variety of advanced permissions options.|

Files and folders inherit the NTFS permissions of their parent folder for ease of administration. An administrator can disable permissions inheritance if permissions do need to be set explicitly. Anytime we see a gray checkmark next to a permission, it was inherited from a parent directory. By default, 

NTFS permissions on files and folders in Windows can be managed using the File Explorer GUI under the security tab. Apart from the GUI, we can also achieve a fine level of granularity over NTFS file permissions in Windows from the command line using the icacls utility.

```
C:\htb> icacls c:\windows
c:\windows NT SERVICE\TrustedInstaller:(F)
           NT AUTHORITY\SYSTEM:(M)
           NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
           BUILTIN\Users:(RX)
```
The resource access level is listed after each user in the output. The possible inheritance settings are:

- (CI): container inherit
- (OI): object inherit
- (IO): inherit only
- (NP): do not propagate inherit
- (I): permission inherited from parent container

Basic access permissions are as follows:

- F : full access
- D :  delete access
- N :  no access
- M :  modify access
- RX :  read and execute access
- R :  read-only access
- W :  write-only access

## Windows Services & Processes

Processes run in the background on Windows systems. They either run automatically as part of the Windows operating system or are started by other installed applications.

Windows services are managed via the Service Control Manager (SCM) system, accessible via the services.msc MMC add-in. Service statuses can appear as Running, Stopped, or Paused, and they can be set to start manually, automatically, or on a delay at system boot. Windows has three categories of services: Local Services, Network Services, and System Services. Services can usually only be created, modified, and deleted by users with administrative privileges. Misconfigurations around service permissions are a common privilege escalation vector on Windows systems.

In Windows, we have some critical system services that cannot be stopped and restarted without a system restart. If we update any file or resource in use by one of these services, we must restart the system.

- smss.exe -	Session Manager SubSystem. Responsible for handling sessions on the system.
- csrss.exe	- Client Server Runtime Process. The user-mode portion of the Windows subsystem.
- wininit.exe	- Starts the Wininit file .ini file that lists all of the changes to be made to Windows when the computer is restarted after installing a program.
- logonui.exe	- Used for facilitating user login into a PC
- lsass.exe	- The Local Security Authentication Server verifies the validity of user logons to a PC or server. It generates the process responsible for authenticating users for the Winlogon service.
- services.exe	- Manages the operation of starting and stopping services.
- winlogon.exe	- Responsible for handling the secure attention sequence, loading a user profile on logon, and locking the computer when a screensaver is running.
System	A background system process that runs the Windows kernel.
- svchost.exe with RPCSS -	Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Remote Procedure Call (RPC) Service (RPCSS).
- svchost.exe with Dcom/PnP -	Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Distributed Component Object Model (DCOM) and Plug and Play (PnP) services.

## Non-Interactive Accounts
Non-interactive accounts in Windows differ from standard user accounts as they do not require login credentials. There are 3 types of non-interactive accounts: the Local System Account, Local Service Account, and the Network Service Account. Non-interactive accounts are generally used by the Windows operating system to automatically start services and applications without requiring user interaction.

|Account|	Description|
|:-:|:-:|
|Local System Account|	Also known as the NT AUTHORITY\SYSTEM account, this is the most powerful account in Windows systems. It is used for a variety of OS-related tasks, such as starting Windows services. This account is more powerful than accounts in the local administrators group.|
|Local Service Account|	Known as the NT AUTHORITY\LocalService account, this is a less privileged version of the SYSTEM account and has similar privileges to a local user account. It is granted limited functionality and can start some services.|
|Network Service Account|	This is known as the NT AUTHORITY\NetworkService account and is similar to a standard domain user account. It has similar privileges to the Local Service Account on the local machine. It can establish authenticated sessions for certain network services.|

## PowerShell

Windows PowerShell is a command shell that was designed by Microsoft to be more geared towards system administrators. PowerShell is built on top of the .NET Framework, which is used for building and running applications on Windows. PowerShell utilizes cmdlets, which are small single-function tools built into the shell. There are more than 100 core cmdlets, and many additional ones have been written, or we can author our own to perform more complex tasks. PowerShell also supports both simple and complex scripts used for system administration tasks, automation, and more. Cmdlets are in the form of Verb-Noun. For example, the command Get-ChildItem can be used to list the current directory. 

Many cmdlets in PowerShell also have aliases. For example, the aliases for the cmdlet Set-Location, to change directories, is either cd or sl. Meanwhile, the aliases for Get-ChildItem are ls and gci. We can view all available aliases by typing Get-Alias.

Sometimes we will find that we are unable to run scripts on a system. This is due to a security feature called the execution policy, which attempts to prevent the execution of malicious scripts. The possible policies are:

|Policy|	Description|
|:-:|:-:|
|AllSigned|	All scripts can run, but a trusted publisher must sign scripts and configuration files. This includes both remote and local scripts. We receive a prompt before running scripts signed by publishers that we have not yet listed as either trusted or untrusted.|
|Bypass|	No scripts or configuration files are blocked, and the user receives no warnings or prompts.|
|Default|	This sets the default execution policy, Restricted for Windows desktop machines and RemoteSigned for Windows servers.|
|RemoteSigned|	Scripts can run but requires a digital signature on scripts that are downloaded from the internet. Digital signatures are not required for scripts that are written locally.|
|Restricted|	This allows individual commands but does not allow scripts to be run. All script file types, including configuration files (.ps1xml), module script files (.psm1), and PowerShell profiles (.ps1) are blocked.|
|Undefined|	No execution policy is set for the current scope. If the execution policy for ALL scopes is set to undefined, then the default execution policy of Restricted will be used.|
|Unrestricted|	This is the default execution policy for non-Windows computers, and it cannot be changed. This policy allows for unsigned scripts to be run but warns the user before running scripts that are not from the local intranet zone.|

The execution policy is not meant to be a security control that restricts user actions. A user can easily bypass the policy by either typing the script contents directly into the PowerShell window, downloading and invoking the script, or specifying the script as an encoded command.

### Windows Management Instrumentation (WMI)

WMI is a subsystem of PowerShell that provides system administrators with powerful tools for system monitoring.
Some of the uses for WMI are:

- Status information for local/remote systems
- Configuring security settings on remote machines/applications
- Setting and changing user and group permissions
- Setting/modifying system properties
- Code execution
- Scheduling processes
- Setting up logging

These tasks can all be performed using a combination of PowerShell and the WMI Command-Line Interface (WMIC). WMI can be run via the Windows command prompt by typing WMIC to open an interactive shell or by running a command directly such as wmic computersystem get name to get the hostname. We can view a listing of WMIC commands and aliases by typing WMIC /?. WMI can also be used with PowerShell by using the Get-WmiObject module. This module is used to get instances of WMI classes or information about available classes. This module can be used against local or remote machines.

## Microsoft Management Console (MMC)
The MMC can be used to group snap-ins, or administrative tools, to manage hardware, software, and network components within a Windows host. We can also use MMC to create custom tools and distribute them to users. MMC works with the concept of snap-ins, allowing administrators to create a customized console with only the administrative tools needed to manage several services. These snap-ins can be added to manage both local and remote systems.

## Windows Subsystem for Linux (WSL)
WSL is a feature that allows Linux binaries to be run natively on Windows and Windows Server 2019 onwards. It was originally intended for developers who needed to run Bash, Ruby, and native Linux command-line tools, directly on their Windows workstation. The second version of WSL, released in May 2019, introduced a real Linux kernel utilizing a subset of Hyper-V features.

WSL can be installed by running the PowerShell command Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux as an Administrator. Once this feature is enabled, we can either download a Linux distro from the Microsoft Store and install it or manually download the Linux distro of our choice and unpack and install it from the command line.

WSL installs an application called Bash.exe, which can be run by merely typing bash into a Windows console to spawn a Bash shell. We have the full look and feel of a Linux host from this shell, including the standard Linux directory structure. We can access the C$ volume and other volumes on the host operating system via the mnt directory.

## Windows Security
### Security Identifier (SID)
SIDs are string values with different lengths, which are stored in the security database. These SIDs are added to the user's access token to identify all actions that the user is authorized to take. A SID consists of the Identifier Authority and the Relative ID (RID). In an Active Directory (AD) domain environment, the SID also includes the domain SID.

### Security Accounts Manager (SAM) and Access Control Entries (ACE)
SAM grants rights to a network to execute specific processes. The access rights themselves are managed by Access Control Entries (ACE) in Access Control Lists (ACL). The ACLs contain ACEs that define which users, groups, or processes have access to a file or to execute a process. The permissions to access a securable object are given by the security descriptor, classified into two types of ACLs: the Discretionary Access Control List (DACL) or System Access Control List (SACL). Every thread and process started or initiated by a user goes through an authorization process. 

### User Account Control (UAC)
User Account Control (UAC) is a security feature in Windows to prevent malware from running or manipulating processes that could damage the computer or its contents. There is the Admin Approval Mode in UAC, which is designed to prevent unwanted software from being installed without the administrator's knowledge or to prevent system-wide changes from being made.

### Registry
The Registry is a hierarchical database in Windows critical for the operating system. It stores low-level settings for the Windows operating system and applications that choose to use it. It is divided into computer-specific and user-specific data. We can open the Registry Editor by typing regedit from the command line or Windows search bar. The tree-structure consists of main folders (root keys) in which subfolders (subkeys) with their entries/files (values) are located. The root keys all start with HKEY. A key such as HKEY-LOCAL-MACHINE is abbreviated to HKLM. HKLM contains all settings that are relevant to the local system.

The entire system registry is stored in several files on the operating system. You can find these under C:\Windows\System32\Config\.

The user-specific registry hive (HKCU) is stored in the user folder (i.e., C:\Users\<USERNAME>\Ntuser.dat).

### Application Whitelisting
An application whitelist is a list of approved software applications or executables allowed to be present and run on a system. The goal is to protect the environment from harmful malware and unapproved software that does not align with the specific business needs of an organization. An organization should implement a whitelist in audit mode initially to make sure that all necessary applications are whitelisted and not blocked by an error of omission. AppLocker is Microsoft's application whitelisting solution and was first introduced in Windows 7. AppLocker gives system administrators control over which applications and files users can run. It gives granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.

Blacklisting specifies a list of harmful or disallowed software/applications to block, and all others are allowed to run/be installed. Whitelisting is based on a "zero trust" principle in which all software/applications are deemed "bad" except for those specifically allowed.

Whitelisting is recommended by organizations such as NIST.

### Local Group Policy
In a domain environment, group policies are pushed down from a Domain Controller onto all domain-joined machines that Group Policy objects (GPOs) are linked to. These settings can also be defined on individual machines using Local Group Policy. Local Group Policy can be used to tweak certain graphical and network settings that are otherwise not accessible via the Control Panel. It can also be used to lock down an individual computer policy with security settings, such as only allowing certain programs to be installed/run or enforcing strict user account password requirements.

### Windows Defender Antivirus
Windows Defender is a built-in antivirus that ships for free with Windows operating systems. We can use the PowerShell cmdlet Get-MpComputerStatus to check which protection settings are enabled. While no antivirus solution is perfect, Windows Defender does very well in monthly detection rate tests compared to other solutions, even paid ones. Since it comes preinstalled as part of the operating system, it does not introduce "bloat" to the system, such as other programs that add browser extensions and trackers. 

  
