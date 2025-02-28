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
