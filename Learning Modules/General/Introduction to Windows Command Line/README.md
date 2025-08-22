# Introduction to Windows Command Line 
Brief notes written to review the material in the HackTheBox module, Introduction to Active Directory.

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

