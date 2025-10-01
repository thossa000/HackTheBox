# Windows Attacks & Defense

Brief notes taken from the Windows Attacks & Defense module in HackTheBox Acedemy to study for the SOC Analyst exam.


## Review of terms
A domain is a group of objects that share the same AD database, such as users or devices.

A tree is one or more domains grouped. Think of this as the domains test.local, staging.test.local, and preprod.test.local, which will be in the same tree under test.local. Multiple trees can exist in this notation.

A forest is a group of multiple trees. This is the topmost level, which is composed of all domains.

Organizational Units (OU) are Active Directory containers containing user groups, Computers, and other OUs.

Trust can be defined as access between resources to gain permission/access to resources in another domain.

Domain Controller is (generally) the Admin of the Active Directory used to set up the entire Directory. The role of the Domain Controller is to provide Authentication and Authorization to different services and users. In Active Directory, the Domain Controller has the topmost priority and has the most authority/privileges.

Active Directory Data Store contains Database files and processes that store and manages directory information for users, services, and applications. Active Directory Data Store contains the file NTDS.DIT, the most critical file within an AD environment; domain controllers store it in the %SystemRoot%\NTDS folder.

LDAP is a protocol that systems in the network environment use to communicate with Active Directory. Domain Controller(s) run LDAP and constantly listen for requests from the network.

Key Distribution Center (KDC): a Kerberos service installed on a DC that creates tickets. Components of the KDC are the authentication server (AS) and the ticket-granting server (TGS).

Kerberos Tickets are tokens that serve as proof of identity (created by the KDC):

- TGT is proof that the client submitted valid user information to the KDC.
- TGS is created for each service the client (with a valid TGT) wants to access.

KDC key is an encryption key that proves the TGT is valid. AD creates the KDC key from the hashed password of the KRBTGT account, the first account created in an AD domain. Although it is a disabled user, KRBTGT has the vital purpose of storing secrets that are randomly generated keys in the form of password hashes. One may never know what the actual password value represents (even if we try to configure it to a known value, AD will automatically override it to a random one).

### Important Ports

- 88: Kerberos.
- 135: WMI/RPC.
- 137-139 & 445: SMB.
- 389 & 636: LDAP.
- 3389: RDP
- 5985 & 5986: PowerShell Remoting (WinRM)

## Kerberoasting
