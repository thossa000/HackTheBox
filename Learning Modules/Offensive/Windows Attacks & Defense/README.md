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
Kerberoasting is a post-exploitation attack that attempts to exploit this behavior by obtaining a ticket and performing offline password cracking to open the ticket. If the ticket opens, then the candidate password that opened the ticket is the service account's password. The success of this attack depends on the strength of the service account's password. Another factor that has some impact is the encryption algorithm used when the ticket is created, with the likely options being:

- AES
- RC4
- DES (found in environments that are 15+ old years old with legacy apps from the early 2000s, otherwise, this will be disabled)

To obtain crackable tickets, we can use Rubeus. When we run the tool with the kerberoast action without specifying a user, it will extract tickets for every user that has an SPN registered.
```
PS C:\Users\bob\Downloads> .\Rubeus.exe kerberoast /outfile:spn.txt
```

We can use hashcat with the hash-mode (option -m) 13100 for a Kerberoastable TGS. We also pass a dictionary file with passwords (the file passwords.txt) and save the output of any successfully cracked tickets to a file called cracked.txt:
```
thossa00@htb[/htb]$ hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"
```

Alternatively, the captured TGS hashes can be cracked with John The Ripper:
```
sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot
```

### Detection
When a TGS is requested, an event log with ID 4769 is generated. However, AD also generates the same event ID whenever a user attempts to connect to a service, which means that the volume of this event is gigantic, and relying on it alone is virtually impossible to use as a detection method.

Even though the general volume of this event is quite heavy, we still can alert against the default option on many tools. When we run 'Rubeus', it will extract a ticket for each user in the environment with an SPN registered; this allows us to alert if anyone generates more than ten tickets within a minute (for example, but it could be less than ten). This event ID should be grouped by the user requesting the tickets and the machine the requests originated from. Ideally, we need to aim to create two separate rules that alert both.

A honeypot user is a perfect detection option to configure in an AD environment; this must be a user with no real use/need in the environment, so no service tickets are generated regularly. In this case, any attempt to generate a service ticket for this account is likely malicious and worth inspecting. 
