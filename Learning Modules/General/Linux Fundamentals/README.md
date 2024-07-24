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
### Working with Files and Directories

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


## Linux Networking

## Linux Hardening

## Linux Distros vs. Solaris
