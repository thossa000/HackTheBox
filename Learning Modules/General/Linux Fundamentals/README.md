# Linux Fundamentals


## Introduction
The Linux kernel and operating system have a complex history, starting with Unix's release in 1970 by AT&T, followed by the BSD in 1977, which faced legal challenges due to its Unix code. Richard Stallman initiated the GNU project in 1983, aiming to create a free Unix-like OS and the GPL. Linux emerged in 1991 as a free kernel by Linus Torvalds, evolving to over 23 million lines of code under the GPL v2. Linux powers over 600 distributions like Ubuntu and Fedora, known for security, frequent updates, and performance, though it lacks beginner-friendliness and broad driver support compared to Windows. It runs on diverse devices, including Android, making it widely installed and versatile.

### Linux Structures
Linux follows 5 principles:

|Principle|Description|
|:-:|:-:|
|1. Everything is a file |All configuration files for the various services running on the Linux operating system are stored in one or more text files.|
|2. Small, single-purpose programs |Linux offers many different tools that we will work with, which can be combined to work together.|
|3. Ability to chain programs together to perform complex tasks | Integrating and combining different tools enables us to carry out many large and complex tasks, such as processing or filtering specific data results.|
|4. Avoid captive user interfaces |Linux is designed to work mainly with the shell (or terminal), which gives the user greater control over the operating system.|
|5. Configuration data stored in a text file |An example of such a file is the /etc/passwd file, which stores all users registered on the system.|

Components of a Linux OS:
|Component|Description|
|:-:|:-:|
|Bootloader|A piece of code that runs to guide the booting process to start the operating system ie. GRUB Bootloader.|
|OS Kernel|The kernel is the main component of an operating system. It manages the resources for system's I/O devices at the hardware level.|
|Daemons|Background services are called "daemons" in Linux. Their purpose is to ensure that key functions such as scheduling, printing, and multimedia are working correctly. These small programs load after we booted or log into the computer.|
|OS Shell|The operating system shell or the command language interpreter (also known as the command line) is the interface between the OS and the user. This interface allows the user to tell the OS what to do. The most commonly used shells are Bash, Tcsh/Csh, Ksh, Zsh, and Fish.|
|Graphics Server|This provides a graphical sub-system (server) called "X" or "X-server" that allows graphical programs to run locally or remotely on the X-windowing system.|
|Window Manager|Also known as a graphical user interface (GUI). There are many options, including GNOME, KDE, MATE, Unity, and Cinnamon. A desktop environment usually has several applications, including file and web browsers. These allow the user to access and manage the essential and frequently accessed features and services of an operating system.|
|Utilities|Applications or utilities are programs that perform particular functions for the user or another program.|

The Linux operating system can be broken down into layers:
|Layer|Description|
|:-:|:-:|
|Hardware|Peripheral devices such as the system's RAM, hard drive, CPU, and others.|
|Kernel|The core of the Linux operating system whose function is to virtualize and control common computer hardware resources like CPU, allocated memory, accessed data, and others. The kernel gives each process its own virtual resources and prevents/mitigates conflicts between different processes.|
|Shell|A command-line interface (CLI), also known as a shell that a user can enter commands into to execute the kernel's functions.|
|System Utility|Makes available to the user all of the operating system's functionality.|

The Linux operating system is structured in a tree-like hierarchy and is documented in the Filesystem Hierarchy Standard (FHS). Linux is structured with the following standard top-level directories:

|Layer|Description|
|:-:|:-:|
|/|The top-level directory is the root filesystem and contains all of the files required to boot the operating system before other filesystems are mounted, as well as the files required to boot the other filesystems. After boot, all of the other filesystems are mounted at standard mount points as subdirectories of the root.|
|/bin|Contains essential command binaries.|
|/boot|Consists of the static bootloader, kernel executable, and files required to boot the Linux OS.|
|/dev| 	Contains device files to facilitate access to every hardware device attached to the system.|
|/etc| 	Local system configuration files. Configuration files for installed applications may be saved here as well.|
|/home| 	Each user on the system has a subdirectory here for storage.|
|/lib| 	Shared library files that are required for system boot.|
|/media| 	External removable media devices such as USB drives are mounted here.|
|/mnt| 	Temporary mount point for regular filesystems.|
|/opt| 	Optional files such as third-party tools can be saved here.|
|/root| 	The home directory for the root user.|
|/sbin| 	This directory contains executables used for system administration (binary system files).|
|/tmp| 	The operating system and many programs use this directory to store temporary files. This directory is generally cleared upon system boot and may be deleted at other times without any warning.|
|/usr| 	Contains executables, libraries, man files, etc.|
|/var| 	This directory contains variable data files such as log files, email in-boxes, web application related files, cron files, and more.|

### Linux Distributions
Linux distributions - or distros - are operating systems based on the Linux kernel. They are used for various purposes, from servers and embedded devices to desktop computers and mobile phones. Each Linux distribution is different, with its own set of features, packages, and tools. The main differences between the various Linux distributions are the included packages, the user interface, and the tools available. 

The main differences between the various Linux distributions are the included packages, the user interface, and the tools available. 
<b>Kali Linux</b> is the most popular distribution for cyber security specialists, including a wide range of security-focused tools and packages. 
<b>Ubuntu</b> is widespread for desktop users, while <b>Debian</b> is popular for servers and embedded systems. Finally, <b>RedHat Enterprise Linux</b> and <b>CentOS</b> are popular for enterprise-level computing.
### Intro to Shell
A Linux terminal, also called a shell or command line, provides a text-based input/output (I/O) interface between users and the kernel for a computer system. The term console is also typical but does not refer to a window but a screen in text mode. In the terminal window, commands can be executed to control the system.

The most commonly used shell in Linux is the Bourne-Again Shell (BASH), and is part of the GNU project. Everything we do through the GUI we can do with the shell. The shell gives us many more possibilities to interact with programs and processes to get information faster. Besides, many processes can be easily automated with smaller or larger scripts that make manual work much easier.

Besides Bash, there also exist other shells like Tcsh/Csh, Ksh, Zsh, Fish shell and others.

## The Shell
### Prompt Description
The home directory for a user is marked with a tilde <~> and is the default folder when we log in.
```
<username>@<hostname>[~]$
```
The dollar sign stands for a user, if logged in as root, the character changes to a hash (#).
Unpriviledged shell prompt - $
Priviledged shell prompt - #

The prompt can be customized by configuring the .bashrc file for the bash shell. For example, we can use: the \u character to represent the current username, \h for the hostname, and \w for the current working directory.

### Getting Help
It is essential to use man pages and help functions to familiarize ourselves with unfamiliar tools and their parameters, as these resources provide detailed manuals and explanations, enabling us to effectively use and discover tricks with various tools.

Example:
```
$man curl

  curl(1)                                                             Curl Manual                                                            curl(1)

NAME
       curl - transfer a URL

SYNOPSIS
       curl [options] [URL...]

DESCRIPTION
       curl  is  a tool to transfer data from or to a server, using one of the supported protocols (DICT, FILE, FTP, FTPS, GOPHER, HTTP, HTTPS,  
       IMAP, IMAPS,  LDAP,  LDAPS,  POP3,  POP3S,  RTMP, RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET, and TFTP). The command is designed to work without user interaction.

       curl offers a busload of useful tricks like proxy support, user authentication, FTP upload, HTTP post, SSL connections, cookies, file transfer resume, Metalink,  and more. As we will see below, the number of features will make our head spin!

       curl is powered by libcurl for all transfer-related features.  See libcurl(3) for details.

Manual page curl(1) line 1 (press h for help or q to quit)
```

### System Information
A list of tools to use to get system information:
|Command|Description|
|:-:|:-:|
|whoami| Displays current username|
|id| Returns users identity|
|hostname| Sets or prints the name of current host system|
|uname| Prints basic information about the operating system name and system hardware|
|pwd|	Returns present working directory name|
|ifconfig| The utility is used to assign or to view an address to a network interface and/or configure network interface parameters|
|ip| A utility to show or manipulate routing, network devices, interfaces and tunnels|
|netstat| Shows network status|
|ss| Another utility to investigate sockets|
|ps| Shows process status|
|who| Displays who is logged in|
|env|	Prints environment or sets and executes command|
|lsblk| Lists block devices|
|lsusb|	Lists USB devices|
|lsof|	Lists open files|
|lspci| Lists PCI devices|
## Workflow
### Navigation
To navigate through the terminal we can use a few basic commands.

pwd - will show the present working directory 

ls - will list the contents in the current directory or one that is specified. Options can be added for additional details .ie '-l' to display more information about the content like type, permission, ownership, size, and creation date.

cd - to change directories. The value '~' will navigate you back to your home directory. and '..' will navigate back to the parent directory.

### Working with Files and Directories
The following commands are used to Create, Move, Copy, and Delete files and directories in the Linux terminal.

|Command|Description|
|:-:|:-:|
|touch| Creates an empty file|
|mkdir| Creates a new directory folder|
|mv| To move a file to another directory, like cut in Windows|
|cp| To copy a file to another directory|
|tree| Shows the whole structure of the parent directory with contents of all child directories|

### Editing Files

Nano and VIM are popular tools used to edit files in the terminal.

Use the help options to learn the ways to interact.

From the command line the 'cat' tool can be used to view files without editing.

### Find Files and Directories

Many tools in the terminal can be used to locate files and directories:

which - locate the file path for an executable. ie. <i>$which python</i>  will return the file path for the python tool <i>/usr/bin/python</i> 

find - used to find files and folders but to also filter results for your search with options.
<i>find <location> <options></i>

locate - the find command is more resource intensive as it searches through the specified directory for all matches. The command locate offers a quicker way to search through the system. In contrast to the find command, locate works with a local database that contains all information about existing files and folders. We can update this database with the <i>$sudo updatedb</i>

### File Descriptors and Redirections
When using search commands in the terminal, 3 data stream components make up the operation.

Data Stream for Input

  STDIN – 0
        
Data Stream for Output

  STDOUT – 1
        
Data Stream for Output that relates to an error occurring.

  STDERR – 2

This allows us to filter the outputs we receive from our search input. ie. <i>find /etc/ -name shadow</i> (this will find all files/directories containing the name shadow in the /etc/ directory.
      
      STDIN - 0 : $find /etc/ -name shadow
      STDOUT - 1: /etc/shadow
      STDERR - 2: find '/etc/ssl/private': Permission denied
                  find '/etc/polkit-1/localauthority': Permission denied

In this case our find command received two errors due to a lack of permissions. This output can be cleaned up to only show expected outputs by redirecting the STDERR - 2 data stream to a file or discarded.

      STDIN - 0 : find /etc/ -name shadow 2>/dev/null
      STDOUT - 1: /etc/shadow
      STDERR - 2: 

All errors are discarded to the null device which discards the data.

Outputting different data streams to files can be handy when keeping records of information:

    find /etc/ -name passwd >> stdout.txt 2>/dev/null

In the example, errors are discarded while expected outputs are appended to a file called stdout.txt.

### Filter Contents
Commands can be used to display file information without an editor. Here are commands that can be used to read a file:

|Command|Description|
|:-:|:-:|
|cat|Display the entire file's content|
|more|Pager tool to scroll through the output of the file, instead of displaying the whole file at once like 'cat'|
|less|Similar to 'more', however quitting the view will with the 'Q' option will remove the displayed file from the terminal unlike 'more'|
|head|Prints the first 10 lines of the file|
|tail|Prints the last 10 lines of the file|
|sort|Sort output alphabetically instead of the original order|
|grep|Search for a match to output in the file|
|cut|Set a delimiter in the file, ie. delimit on each "-d':'" for the first position, "-f1":  cut -d":" -f1|
|tr|Replace characters in the output with a specified output, ie. tr ":" " ", this will replace each  ":" with a space|
|column|Sort information into a table|
|awk|Prints the specified position for each row in a file, if you only want to see the first and last value of each row, use the following: awk '{print $1, $NF}'|
|sed|Modify the output by replacing specified values with another, to replace 'root' with 'admin' in your output use: sed 's/root/admin/g'|
|wc|Counts the number of specified values in the output (specify with options for the wc command ie. -l for lines)|

### Regular Expression
A regular expression is a sequence of letters and symbols forming a search pattern, enhanced by metacharacters, used in tools like grep or sed and commonly implemented in web applications for validating user input.

<table>
  <tr>
    <th>Expression</th>
    <th>Description</th>
  </tr>
  <tr>
    <td align="center">(a)</td>
    <td>The round brackets are used to group parts of a regex. Within the brackets, you can define further patterns which should be processed together.</td>
  </tr>
  <tr>
    <td align="center">[a-z]</td>
    <td>The square brackets are used to define character classes. Inside the brackets, you can specify a list of characters to search for.</td>
  </tr>
  <tr>
    <td align="center">{1,10}</td>
    <td>The curly brackets are used to define quantifiers. Inside the brackets, you can specify a number or a range that indicates how often a previous pattern should be repeated.</td>
  </tr>
  <tr>
    <td align="center">|</td>
    <td>Also called the OR operator and shows results when one of the two expressions matches</td>
  </tr>
  <tr>
    <td align="center">.*</td>
    <td>Also called the AND operator and displayed results only if both expressions match</td>
  </tr>
</table>

### Permission Management

The whole permission system on Linux systems is based on the octal number system, and basically, there are three different types of permissions a file or directory can be assigned:

(r) - Read

(w) - Write

(x) - Execute


## System Management
### User Management

### Package Management
It is crucial to understand Linux package managers and their usage for installing, updating, or removing packages, whether maintaining systems professionally or personally, as these managers handle software binaries, configuration files, dependencies, and updates.
The features that most package management systems provide are:
- Package downloading
- Dependency resolution
- A standard binary package format
- Common installation and configuration locations
- Additional system-related configuration and functionality
- Quality control

Here is a list of different package management programs:
|Command|Description|
|:-:|:-:|
|dpkg|The dpkg is a tool to install, build, remove, and manage Debian packages. The primary and more user-friendly front-end for dpkg is aptitude.|
|apt|Apt provides a high-level command-line interface for the package management system.|
|aptitude|Aptitude is an alternative to apt and is a high-level interface to the package manager.|
|snap|Install, configure, refresh, and remove snap packages. Snaps enable the secure distribution of the latest apps and utilities for the cloud, servers, desktops, and the internet of things.|
|gem|Gem is the front-end to RubyGems, the standard package manager for Ruby.|
|pip|Pip is a Python package installer recommended for installing Python packages that are not available in the Debian archive. It can work with version control repositories (currently only Git, Mercurial, and Bazaar repositories), logs output extensively, and prevents partial installs by downloading all requirements before starting installation.|
|git|Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals.|

### Service and Process Management
There are two types of services, internal services required by the system to run, such services run in the background without any user interaction. These are also called daemons and are identified by the letter 'd' at the end of the program name, for example, sshd or systemd. 
Second are user services that are installed and ran by the user.

There are three possibilities to run several commands, one after the other. These are separated by:

- Semicolon (;)
- Double ampersand characters (&&)
- Pipes (|)
  
### Task Scheduling
Task scheduling is a feature in Linux systems that allows users to schedule and automate tasks at specified times and frequencies. Examples include automatically updating software, running scripts, cleaning databases, and automating backups.

Cron is a tool commonly used to automate tasks. Systemd can also be used to setup scheduled jobs by creating a timer and service then activating the timer when required.
To set up the cron daemon, we need to store the tasks in a file called crontab and then tell the daemon when to run the tasks. 
A crontab file holds the time frequency and name of the script that will run:

```
# System Update
* */6 * * /path/to/update_software.sh

# Execute scripts
0 0 1 * * /path/to/scripts/run_scripts.sh

# Cleanup DB
0 0 * * 0 /path/to/scripts/clean_database.sh

# Backups
0 0 * * 7 /path/to/scripts/backup.sh
```

### Network Services
SSH - is widely used to securely manage remote systems and securely access remote systems to execute commands or transfer files. The most commonly used SSH server is the OpenSSH server.

NFS - a network protocol that allows us to store and manage files on remote systems as if they were stored on the local system. For Linux, there are several NFS servers, including NFS-UTILS (Ubuntu), NFS-Ganesha (Solaris), and OpenNFS (Redhat Linux). We can configure NFS via the configuration file /etc/exports.

VPN - is a technology that allows us to connect securely to another network as if we were directly in it. This is done by creating an encrypted tunnel connection between the client and the server, which means that all data transmitted over this connection is encrypted.

cURL - is a tool that allows us to transfer files from the shell over protocols like HTTP, HTTPS, FTP, SFTP, FTPS, or SCP.

Wget - An alternative to cURL. With this tool, we can download files from FTP or HTTP servers directly from the terminal, and it serves as a good download manager. Useful when website content needs to be downloaded and stored instead of just viewed.
## Linux Networking
XServer - Graphical remoting tool, uses X11 protocol on ports 6000-6009. GUI is generated on local machine instead of on target machine, saving bandwidth to transport GUI data over the network. X11 is vulnerable due to transmitting unencrypted data, however this is resolved by tunelling traffic through SSH, configured in /etc/ssh/sshd_config.

The X Display Manager Control Protocol (XDMCP) protocol is used by the X Display Manager for communication through UDP port 177. This is used to manage multiple sessions on other machines. XDMCP is vulnerable to MITM attacks to run arbitrary commands, access sensitive data, or perform other actions that could compromise the security of the system.

Virtual Network Computing (VNC) is based on the RFB protocol and one of the most common remote desktop sharing tools, this is generally considered secure, using encryption in transit and authentication for sessions. VNC normally listens on TCP port 5900, addtional displays for a host can be added through ports 590X. 
## Linux Hardening
Ensure OS and packages are updated reguarly to receive latest security patches.

Configure Firewall rules and/or iptable to restrict network port traffic in/out of hosts. Also configuring TCPWrapper through hosts allow/deny configuration files to restrict remote access to services.

Enforcing principal of least privilege for server access. Ex. Having root login disabled in SSH. Configuring allowed sudoers on the host. 

Configure audit logs of activity on hosts, to allow for the option to review host activity to identify signs of potential compromise or misconfigurations. 

Enable security modules such as AppArmor of SELinux to enforce standard security policies.

In addition, some security settings should be made, such as:

- Removing or disabling all unnecessary services and software
- Removing all services that rely on unencrypted authentication mechanisms
- Ensure NTP is enabled and Syslog is running
- Ensure that each user has its own account
- Enforce the use of strong passwords
- Set up password aging and restrict the use of previous passwords
- Locking user accounts after login failures
- Disable all unwanted SUID/SGID binaries
