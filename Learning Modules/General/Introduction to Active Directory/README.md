# Introduction to Active Directory
Brief notes written to review the material in the HackTheBox module, Introduction to Active Directory.

Active Directory (AD) is a directory service for Windows network environments. It is a distributed, hierarchical structure that allows for centralized management of an organization's resources, including users, computers, groups, network devices and file shares, group policies, servers and workstations, and trusts. AD provides authentication and authorization functions within a Windows domain environment. A directory service, such as Active Directory Domain Services (AD DS) gives an organization ways to store directory data and make it available to both standard users and administrators on the same network.

## Active Directory Structure
Active Directory flaws and misconfigurations can often be used to obtain a foothold (internal access), move laterally and vertically within a network, and gain unauthorized access to protected resources such as databases, file shares, source code, and more. AD is essentially a large database accessible to all users within the domain, regardless of their privilege level. A basic AD user account with no added privileges can be used to enumerate the majority of objects contained within AD, including but not limited to:

- Domain Computers	
- Domain Users
- Domain Group Information
- Organizational Units (OUs)
- Default Domain Policy
- Functional Domain Levels
- Password Policy
- Group Policy Objects (GPOs)
- Domain Trusts
- Access Control Lists (ACLs)

Active Directory is arranged in a hierarchical tree structure, with a forest at the top containing one or more domains, which can themselves have nested subdomains. A forest is the security boundary within which all objects are under administrative control.  A domain is a structure within which contained objects (users, computers, and groups) are accessible. OUs may contain objects and sub-OUs, allowing for the assignment of different group policies.

An AD structure may look like:
```
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

## Active Directory Terminology

|Term|Definition|
|:-:|:-:|
|Object| any resource present within an Active Directory environment such as OUs, printers, users, domain controllers, etc.
|Attributes| Every object in Active Directory has an associated set of attributes used to define characteristics of the given object.
|Schema| The blueprint of any enterprise environment. It defines what types of objects can exist in the AD database and their associated attributes.
|Domain| A logical group of objects such as computers, users, OUs, groups, etc. We can think of each domain as a different city within a state or country.
|Forest| A forest is a collection of Active Directory domains. It is the topmost container and contains all of the AD objects introduced below.
|Tree| A tree is a collection of Active Directory domains that begins at a single root domain. A forest is a collection of AD trees. Each domain in a tree shares a boundary with the other domains.
|Container| Container objects hold other objects and have a defined place in the directory subtree hierarchy.
|Leaf| Leaf objects do not contain other objects and are found at the end of the subtree hierarchy.
|Global Unique Identifier (GUID)| A GUID is a unique 128-bit value assigned when a domain user or group is created. This GUID value is unique across the enterprise, similar to a MAC address.
|Security principals| Domain objects that can manage access to other resources within the domain.
|Security Identifier (SID)| SID is used as a unique identifier for a security principal or security group. Every account, group, or process has its own unique SID, which, in an AD environment, is issued by the domain controller and stored in a secure database.
|Distinguished Name (DN)| Describes the full path to an object in AD (such as cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local).
|Relative Distinguished Name (RDN)| A single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy. RDN must be unique in the OU.
|sAMAccountName| The sAMAccountName is the user's logon name. It must be a unique value and 20 or fewer characters.
|userPrincipalName| Another way to identify users in AD. This attribute consists of a prefix (the user account name) and a suffix (the domain name) in the format of bjones@inlanefreight.local. This attribute is not mandatory.
|Flexible Single Master Operation (FSMO) Roles| These give Domain Controllers (DC) the ability to continue authenticating users and granting permissions without interruption (authorization and authentication).
|Global Catalog| A domain controller that stores copies of ALL objects in an Active Directory forest
|Read-Only Domain Controller (RODC)| Read-only Active Directory database. No AD account passwords are cached on an RODC. No changes are pushed out via an RODC's AD database, SYSVOL, or DNS. RODCs also include a read-only DNS server, allow for administrator role separation, reduce replication traffic in the environment, and prevent SYSVOL modifications from being replicated to other DCs.
|Replication| When AD objects are updated and transferred from one Domain Controller to another.
|Service Principal Name (SPN)| Uniquely identifies a service instance. They are used by Kerberos authentication to associate an instance of a service with a logon account.
|Group Policy Object (GPO)| Virtual collections of policy settings. Each GPO has a unique GUID. A GPO can contain local file system settings or Active Directory settings.
|Access Control List (ACL)| An Access Control List (ACL) is the ordered collection of Access Control Entries (ACEs) that apply to an object.
|Access Control Entries (ACEs)| Each Access Control Entry (ACE) in an ACL identifies a trustee (user account, group account, or logon session) and lists the access rights that are allowed, denied, or audited for the given trustee.
|Discretionary Access Control List (DACL)| When a process tries to access a securable object, the system checks the ACEs in the object's DACL to determine whether or not to grant access.
|System Access Control Lists (SACL)| Allows for administrators to log access attempts that are made to secured objects.
|Fully Qualified Domain Name (FQDN)| An FQDN is the complete name for a specific computer or host. It is written with the hostname and domain name in the format [host name].[domain name].[tld].
|Tombstone| A tombstone is a container object in AD that holds deleted AD objects.
|AD Recycle Bin| Facilitates the recovery of deleted AD objects. This made it easier for sysadmins to restore objects, avoiding the need to restore from backups.
|SYSVOL| The SYSVOL folder, or share, stores copies of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, and often contains other types of scripts that are executed to perform various tasks in the AD environment.
|AdminSDHolder| This object is used to manage ACLs for members of built-in groups in AD marked as privileged. It acts as a container that holds the Security Descriptor applied to members of protected groups.
|dsHeuristics| This attribute is a string value set on the Directory Service object used to define multiple forest-wide configuration settings. One of these settings is to exclude built-in groups from the Protected Groups list.
|adminCount| This attribute determines whether or not the SDProp process protects a user. If the value is set to 0 or not specified, the user is not protected. If the attribute value is set to 1, the user is protected.
|Active Directory Users and Computers (ADUC)| ADUC is a GUI console commonly used for managing users, groups, computers, and contacts in AD. Changes made in ADUC can be done via PowerShell as well.
|ADSI Edit| A GUI tool used to manage objects in AD. It provides access to far more than is available in ADUC and can be used to set or delete any attribute available on an object, add, remove, and move objects as well.
|MSBROWSE| A Microsoft networking protocol that was used in early versions of Windows-based local area networks (LANs) to provide browsing services. It was used to maintain a list of resources, such as shared printers and files, that were available on the network, and to allow users to easily browse and access these resources. Today, MSBROWSE is largely obsolete.
|sIDHistory| This attribute holds any SIDs that an object was assigned previously. It is usually used in migrations so a user can maintain the same level of access when migrated from one domain to another.
|NTDS.DIT| The NTDS.DIT file can be considered the heart of Active Directory. It is stored on a Domain Controller at C:\Windows\NTDS\ and is a database that stores AD data such as information about user and group objects, group membership, and, most important to attackers and penetration testers, the password hashes for all users in the domain.

## Active Directory Objects
|Object|Traits|
|:-:|:-:|
|Users| Users are considered leaf objects, which means that they cannot contain any other objects within them. Another example of a leaf object is a mailbox in Microsoft Exchange.
|Contacts| Leaf objects. Usually used to represent an external user and contains informational attributes such as first name, last name, email address, and telephone number. NOT security principals (securable objects), so they don't have a SID, only a GUID.
|Printers| A leaf object and not a security principal, so it only has a GUID. Printers have attributes such as the printer's name, driver information, port number, etc.
|Computers| Leaf objects because they do not contain other objects. However, they are considered security principals and have a SID and a GUID. Like users, they are prime targets for attackers.
|Shared Folders| A shared folder object points to a shared folder on the specific computer where the folder resides. Shared folders can have stringent access control applied to them. NOT security principals and only have a GUID.
|Groups| A container object because it can contain other objects, including users, computers, and even other groups. A group IS regarded as a security principal and has a SID and a GUID. In AD, groups are a way to manage user permissions and access to other securable objects (both users and computers).
|Organizational Units (OUs)| A container that systems administrators can use to store similar objects for ease of administration. OUs are often used for administrative delegation of tasks without granting a user account full administrative rights. OUs are very useful for managing Group Policy.
|Domain| A domain is the structure of an AD network. Domains contain objects such as users and computers, which are organized into container objects: groups and OUs. 
|Domain Controllers| They handle authentication requests, verify users on the network, and control who can access the various resources in the domain. All access requests are validated via the domain controller and privileged access requests are based on predetermined roles assigned to users.
|Sites| A site in AD is a set of computers across one or more subnets connected using high-speed links. They are used to make replication across domain controllers run efficiently.
|Built-in| In AD, built-in is a container that holds default groups in an AD domain. They are predefined when an AD domain is created.
|Foreign Security Principals| an object created in AD to represent a security principal that belongs to a trusted external forest. They are created when an object such as a user, group, or computer from an external forest is added to a group in the current domain.

## Active Directory Functionality
###  Flexible Single Master Operation (FSMO) roles

|Roles	|Description|
|:-:|:-:|
|Schema Master	|This role manages the read/write copy of the AD schema, which defines all attributes that can apply to an object in AD.
|Domain Naming Master|	Manages domain names and ensures that two domains of the same name are not created in the same forest.
|Relative ID (RID) Master|	The RID Master assigns blocks of RIDs to other DCs within the domain that can be used for new objects. The RID Master helps ensure that multiple objects are not assigned the same SID. Domain object SIDs are the domain SID combined with the RID number assigned to the object to make the unique SID.
|PDC Emulator|	The host with this role would be the authoritative DC in the domain and respond to authentication requests, password changes, and manage Group Policy Objects (GPOs). The PDC Emulator also maintains time within the domain.
|Infrastructure Master|	This role translates GUIDs, SIDs, and DNs between domains. This role is used in organizations with multiple domains in a single forest. The Infrastructure Master helps them to communicate. If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names.

### Trust
A trust is used to establish forest-forest or domain-domain authentication, allowing users to access resources in (or administer) another domain outside of the domain their account resides in. 
|Trust Type	|Description|
|:-:|:-:|
|Parent-child	|Domains within the same forest. The child domain has a two-way transitive trust with the parent domain.
|Cross-link	|a trust between child domains to speed up authentication.
|External	|A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering.
|Tree-root	|a two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
|Forest	|a transitive trust between two forest root domains.

## Kerberos, DNS, LDAP, MSRPC
### Kerberos
Kerberos has been the default authentication protocol for domain accounts since Windows 2000. Kerberos is an open standard and allows for interoperability with other systems using the same standard. When a user logs into their PC, Kerberos is used to authenticate them via mutual authentication, or both the user and the server verify their identity.
Trusts can be transitive or non-transitive.

- A transitive trust means that trust is extended to objects that the child domain trusts.
- In a non-transitive trust, only the child domain itself is trusted.

### Kerberos Authentication Process

1. When a user logs in, their password is used to encrypt a timestamp, which is sent to the Key Distribution Center (KDC) to verify the integrity of the authentication by decrypting it. The KDC then issues a Ticket-Granting Ticket (TGT), encrypting it with the secret key of the krbtgt account. This TGT is used to request service tickets for accessing network resources, allowing authentication without repeatedly transmitting the user's credentials. This process decouples the user's credentials from requests to resources.
2. The KDC service on the DC checks the authentication service request (AS-REQ), verifies the user information, and creates a Ticket Granting Ticket (TGT), which is delivered to the user.
3. The user presents the TGT to the DC, requesting a Ticket Granting Service (TGS) ticket for a specific service. This is the TGS-REQ. If the TGT is successfully validated, its data is copied to create a TGS ticket.
4. The TGS is encrypted with the NTLM password hash of the service or computer account in whose context the service instance is running and is delivered to the user in the TGS_REP.
5. The user presents the TGS to the service, and if it is valid, the user is permitted to connect to the resource (AP_REQ)

The Kerberos protocol uses port 88 (both TCP and UDP). When enumerating an Active Directory environment, we can often locate Domain Controllers by performing port scans looking for open port 88 using a tool such as Nmap.

### DNS 
DNS is used to resolve hostnames to IP addresses and is broadly used across internal networks and the internet. Private internal networks use Active Directory DNS namespaces to facilitate communications between servers, clients, and peers. AD maintains a database of services running on the network in the form of service records (SRV). These service records allow clients in an AD environment to locate services that they need, such as a file server, printer, or Domain Controller.

### LDAP
LDAP is an open-source and cross-platform protocol used for authentication against various directory services (such as AD). LDAP uses port 389, and LDAP over SSL (LDAPS) communicates over port 636. LDAP is the language that applications use to communicate with other servers that provide directory services. In other words, LDAP is how systems in the network environment can "speak" to AD.

An LDAP session begins by first connecting to an LDAP server, also known as a Directory System Agent. The Domain Controller in AD actively listens for LDAP requests, such as security authentication requests.

### AD LDAP Authentication
LDAP is set up to authenticate credentials against AD using a "BIND" operation to set the authentication state for an LDAP session. There are two types of LDAP authentication.

1. Simple Authentication: This includes anonymous authentication, unauthenticated authentication, and username/password authentication. Simple authentication means that a username and password create a BIND request to authenticate to the LDAP server.

2. SASL Authentication: The Simple Authentication and Security Layer (SASL) framework uses other authentication services, such as Kerberos, to bind to the LDAP server and then uses this authentication service (Kerberos in this example) to authenticate to LDAP. The LDAP server uses the LDAP protocol to send an LDAP message to the authorization service, which initiates a series of challenge/response messages resulting in either successful or unsuccessful authentication. SASL can provide additional security due to the separation of authentication methods from application protocols.

### MSRPC
Windows systems use MSRPC (MS Remote Procedure Call) to access systems in Active Directory using four key RPC interfaces.

|Interface Name|	Description|
|:-:|:-:|
|lsarpc|	A set of RPC calls to the Local Security Authority (LSA) system which manages the local security policy on a computer, controls the audit policy, and provides interactive authentication services. LSARPC is used to perform management on domain security policies.
|netlogon|	Netlogon is a Windows process used to authenticate users and other services in the domain environment. It is a service that continuously runs in the background.
|samr|	Remote SAM (samr) provides management functionality for the domain account database, storing information about users and groups. IT administrators use the protocol to manage users, groups, and computers by enabling admins to create, read, update, and delete information about security principles. Attackers (and pentesters) can use the samr protocol to perform reconnaissance about the internal domain using tools such as BloodHound to visually map out the AD network and create "attack paths" to illustrate visually how administrative access or full domain compromise could be achieved. Organizations can protect against this type of reconnaissance by changing a Windows registry key to only allow administrators to perform remote SAM queries since, by default, all authenticated domain users can make these queries to gather a considerable amount of information about the AD domain.
|drsuapi|	drsuapi is the Microsoft API that implements the Directory Replication Service (DRS) Remote Protocol which is used to perform replication-related tasks across Domain Controllers in a multi-DC environment. Attackers can utilize drsuapi to create a copy of the Active Directory domain database (NTDS.dit) file to retrieve password hashes for all accounts in the domain, which can then be used to perform Pass-the-Hash attacks to access more systems or cracked offline using a tool such as Hashcat to obtain the cleartext password to log in to systems using remote management protocols such as Remote Desktop (RDP) and WinRM.

## NTLM Authentication

|Hash/Protocol|	Cryptographic technique|	Mutual Authentication|	Message Type|	Trusted Third Party|
|:-:|:-:|:-:|:-:|:-:|
|NTLM|	Symmetric key cryptography|	No|	Random number|	Domain Controller
|NTLMv1|	Symmetric key cryptography|	No|	MD4 hash, random number|	Domain Controller
|NTLMv2|	Symmetric key cryptography|	No|	MD4 hash, random number|	Domain Controller
|Kerberos|	Symmetric key cryptography & asymmetric cryptography|	Yes|	Encrypted ticket using DES, MD5	Domain| Controller/Key Distribution Center (KDC)

NT LAN Manager (NTLM) hashes are used on modern Windows systems. It is a challenge-response authentication protocol and uses three messages to authenticate: a client first sends a NEGOTIATE_MESSAGE to the server, whose response is a CHALLENGE_MESSAGE to verify the client's identity. Lastly, the client responds with an AUTHENTICATE_MESSAGE. These hashes are stored locally in the SAM database or the NTDS.DIT database file on a Domain Controller. The protocol has two hashed password values to choose from to perform authentication: the LM hash and the NT hash, which is the MD4 hash of the little-endian UTF-16 value of the password. GPU attacks have shown that the entire NTLM 8 character keyspace can be brute-forced in under 3 hours. Longer NTLM hashes can be more challenging to crack depending on the password chosen, and even long passwords (15+ characters) can be cracked using an offline dictionary attack combined with rules. NTLM is also vulnerable to the pass-the-hash attack.

### NTLMv2 (Net-NTLMv2)
The NTLMv2 protocol was first introduced in Windows NT 4.0 SP4 and was created as a stronger alternative to NTLMv1. It has been the default in Windows since Server 2000. It is hardened against certain spoofing attacks that NTLMv1 is susceptible to. NTLMv2 sends two responses to the 8-byte challenge received by the server. These responses contain a 16-byte HMAC-MD5 hash of the challenge, a randomly generated challenge from the client, and an HMAC-MD5 hash of the user's credentials. A second response is sent, using a variable-length client challenge including the current time, an 8-byte random value, and the domain name.

### Domain Cached Credentials (MSCache2)
Microsoft developed the MS Cache v1 and v2 algorithm (also known as Domain Cached Credentials (DCC) to solve the potential issue of a domain-joined host being unable to communicate with a domain controller (i.e., due to a network outage or other technical issue) and, hence, NTLM/Kerberos authentication not working to access the host in question. Hosts save the last ten hashes for any domain users that successfully log into the machine in the HKEY_LOCAL_MACHINE\SECURITY\Cache registry key. These hashes cannot be used in pass-the-hash attacks. Furthermore, the hash is very slow to crack with a tool such as Hashcat.

## User and Machine Accounts
User accounts are created on both local systems (not joined to AD) and in Active Directory to give a person or a program (such as a system service) the ability to log on to a computer and access resources based on their rights. When a user logs in, the system verifies their password and creates an access token. This token describes the security content of a process or thread and includes the user's security identity and group membership.

It can be easier for an administrator to assign privileges once to a group (which all group members inherit) instead of many times to each individual user. Some companies must retain records of these accounts for audit purposes, so they will deactivate them (and hopefully remove all privileges) once the employee is terminated, but they will not delete them. It is common to see an OU such as FORMER EMPLOYEES that will contain many deactivated accounts.

### Local Accounts

- Administrator: this account has the SID S-1-5-domain-500 and is the first account created with a new Windows installation.
- Guest: this account is disabled by default. The purpose of this account is to allow users without an account on the computer to log in temporarily with limited access rights.
- SYSTEM: The SYSTEM (or NT AUTHORITY\SYSTEM) account on a Windows host is the default account installed and used by the operating system to perform many of its internal functions.
- Network Service: This is a predefined local account used by the Service Control Manager (SCM) for running Windows services.
- Local Service: This is another predefined local account used by the Service Control Manager (SCM) for running Windows services.

### Domain Users
Domain users differ from local users in that they are granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on the permissions granted to their user account or the group that account is a member of. Domain user accounts can log in to any host in the domain, unlike local users.

One account to keep in mind is the KRBTGT account. This is a type of local account built into the AD infrastructure. This account acts as a service account for the Key Distribution service providing authentication and access for domain resources. This account is a common target of many attackers since gaining control or access will enable an attacker to have unconstrained access to the domain.

### User Naming Attributes

|Attribute| Description|
|:-:|:-:|
|UserPrincipalName (UPN)|	This is the primary logon name for the user. By convention, the UPN uses the email address of the user.
|ObjectGUID|	This is a unique identifier of the user. In AD, the ObjectGUID attribute name never changes and remains unique even if the user is removed.
|SAMAccountName|	This is a logon name that supports the previous version of Windows clients and servers.
|objectSID	|The user's Security Identifier (SID). This attribute identifies a user and its group memberships during security interactions with the server.
|sIDHistory|	This contains previous SIDs for the user object if moved from another domain and is typically seen in migration scenarios from domain to domain. After a migration occurs, the last SID will be added to the sIDHistory property, and the new SID will become its objectSID.

## Active Directory Groups
Groups are another key target for attackers and penetration testers, as the rights that they confer on their members may not be readily apparent but may grant excessive access. There are many built-in groups in Active Directory, and most organizations also create their own groups to define rights and privileges, further managing access within the domain. Groups are primarily used to assign permissions to access resources. OUs can also be used to delegate administrative tasks to a user, such as resetting passwords or unlocking user accounts without giving them additional admin rights that they may inherit through group membership.

### Group Types
Groups in Active Directory have two fundamental characteristics: type and scope. The group type defines the group's purpose, while the group scope shows how the group can be used within the domain or forest. When creating a new group, we must select a group type. There are two main types: security and distribution groups.

The Security groups type is primarily for ease of assigning permissions and rights to a collection of users instead of one at a time.

The Distribution groups type is used by email applications such as Microsoft Exchange to distribute messages to group members. This type of group cannot be used to assign permissions to resources in a domain environment.

### Group Scopes
There are three different group scopes that can be assigned when creating a new group.

1. Domain Local Group
2. Global Group
3. Universal Group

![image](https://github.com/user-attachments/assets/c84dc14a-1723-43b3-ac8f-1aa6049de774)

#### Domain Local Group
Domain local groups can only be used to manage permissions to domain resources in the domain where it was created. Local groups cannot be used in other domains but CAN contain users from OTHER domains. Local groups can be nested into (contained within) other local groups but NOT within global groups.

#### Global Group
Global groups can be used to grant access to resources in another domain. A global group can only contain accounts from the domain where it was created. Global groups can be added to both other global groups and local groups.

#### Universal Group
The universal group scope can be used to manage resources distributed across multiple domains and can be given permissions to any object within the same forest. They are available to all domains within an organization and can contain users from any domain. Unlike domain local and global groups, universal groups are stored in the Global Catalog (GC), and adding or removing objects from a universal group triggers forest-wide replication. It is recommended that administrators maintain other groups (such as global groups) as members of universal groups because global group membership within universal groups is less likely to change than individual user membership in global groups. Replication is only triggered at the individual domain level when a user is removed from a global group.

### Nested Group Membership
Tools like BloodHound are  useful in uncovering privileges that a user may inherit through one or more nestings of groups. This is a key tool for penetration testers for uncovering misconfigurations and is also extremely powerful for sysadmins and the like to gain deep insights into the security posture of their domain(s).

### Group Attributes
cn: The cn or Common-Name is the name of the group in Active Directory Domain Services.

member: Which user, group, and contact objects are members of the group.

groupType: An integer that specifies the group type and scope.

memberOf: A listing of any groups that contain the group as a member (nested group membership).

objectSid: This is the security identifier or SID of the group, which is the unique value used to identify the group as a security principal.

#### User Privileges
After logging into a host, typing the command whoami /priv will give us a listing of all user rights assigned to the current user. 

## General Active Directory Hardening
### LAPS
The Microsoft Local Administrator Password Solution (LAPS) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.

### Audit Policy Settings (Logging and Monitoring)
Effective logging and monitoring can be used to detect an attacker or unauthorized employee adding a user or computer, modifying an object in AD, changing an account password, accessing a system in an unauthorized or non-standard manner, performing an attack such as password spraying, or more advanced attacks such as modern Kerberos attacks.

### Group Policy Security Settings
Group Policy Objects (GPOs) are virtual collections of policy settings that can be applied to specific users, groups, and computers at the OU level. These can be used to apply a wide variety of security policies to help harden Active Directory.

- Account Policies
- Local Policies
- Software Restriction Policies
- Application Control Policies
- Advanced Audit Policy Configuration

### Update Management (SCCM/WSUS)
The Windows Server Update Service (WSUS) can be installed as a role on a Windows Server and can be used to minimize the manual task of patching Windows systems. System Center Configuration Manager (SCCM) is a paid solution that relies on the WSUS Windows Server role being installed and offers more features than WSUS on its own. 

### Group Managed Service Accounts (gMSA)
An account managed by the domain that offers a higher level of security than other types of service accounts for use with non-interactive applications, services, processes, and tasks that are run automatically but require credentials to run. They provide automatic password management with a 120 character password generated by the domain controller. The password is changed at a regular interval and does not need to be known by any user. It allows for credentials to be used across multiple hosts.

### Security Groups
Active Directory automatically creates some default security groups during installation. Some examples are Account Operators, Administrators, Backup Operators, Domain Admins, and Domain Users. These groups can also be used to assign permission to access resources (i.e., a file share, folder, printer, or a document). Security groups help ensure you can assign granular permissions to users instead of individually managing each user.

### Account Separation
Administrators must have two separate accounts. One for their day-to-day work and a second for any administrative tasks they must perform.

### Password Complexity Policies + MFA
The minimum password length for standard users should be at least 12 characters and ideally longer for administrators/service accounts. Another important security measure is the implementation of multi-factor authentication (MFA) for Remote Desktop Access to any host. This can help to limit lateral movement attempts that may rely on GUI access to a host.

### Limiting Domain Admin Account Usage
All-powerful Domain Admin accounts should only be used to log in to Domain Controllers, not personal workstations, jump hosts, web servers, etc. This can significantly reduce the impact of an attack and cut down potential attack paths should a host be compromised. This would ensure that Domain Admin account passwords are not left in memory on hosts throughout the environment.

### Auditing Permissions and Access
Organizations should  periodically perform access control audits to ensure that users only have the level of access required for their day-to-day work. It is important to audit local admin rights, the number of Domain Admins, and Enterprise Admins to limit the attack surface, file share access, user rights (i.e., membership in certain privileged security groups), and more. Usage of these high privilege accounts should also be audited to ensure no breaches to policy and standard procedures.

### Audit Policies & Logging
Visibility into the domain is a must. An organization can achieve this through robust logging and then using rules to detect anomalous activity. These can also be used to detect Active Directory enumeration.

### Using Restricted Groups
Restricted Groups allow for administrators to configure group membership via Group Policy. They can be used for a number of reasons, such as controlling membership in the local administrator's group on all hosts in the domain by restricting it to just the local Administrator account and Domain Admins and controlling membership in the highly privileged Enterprise Admins and Schema Admins groups and other key administrative groups.

### Limiting Server Roles
It is important not to install additional roles on sensitive hosts, such as installing the Internet Information Server (IIS) role on a Domain Controller. This would increase the attack surface of the Domain Controller, and this type of role should be installed on a separate standalone web server. This type of role separation can help to reduce the impact of a successful attack.

### Limiting Local Admin and RDP Rights
Organizations should tightly control which users have local admin rights on which computers. The same goes for Remote Desktop (RDP) rights. If many users can RDP to one or many machines, this increases the risk of sensitive data exposure or potential privilege escalation attacks, leading to further compromise.

