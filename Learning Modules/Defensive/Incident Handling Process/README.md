# Incident Handling Process
Brief notes written to review the material in the HackTheBox module, Incident Handling Process.

An event is an action occurring in a system or network. Examples of events are:

- A user sending an email
- A mouse click
- A firewall allowing a connection request

An incident is an event with a negative consequence. One example of an incident is a system crash. Another example is unauthorized access to sensitive data. Incidents can also occur due to natural disasters, power failures, etc. An IT security incident as an event with a clear intent to cause harm that is performed against a computer system. Examples of incidents are:

- Data theft
- Funds theft
- Unauthorized access to data
- Installation and usage of malware and remote access tools

Incident handling is a clearly defined set of procedures to manage and respond to security incidents in a computer or network environment.

Other types of incidents other than IT Security incidents, such as malicious insiders, availability issues, and loss of intellectual property, also fall within the scope of incident handling. A comprehensive incident handling plan should address various types of incidents and provide appropriate measures to identify, contain, eradicate, and recover from them to restore normal business operations as quickly and efficiently as possible.

It may not be immediately clear that an event is an incident, until an initial investigation is performed. There are some suspicious events that should be treated as incidents unless proven otherwise.

The incident handling team is led by an incident manager. This role is often assigned to a SOC manager, CISO/CIO, or third-party (trusted) vendor, and this person usually has the ability to direct other business units as well. If necessary. The incident manager is the single point of communication who tracks the activities taken during the investigation and their status of completion.

## Cyber Kill Chain
This lifecycle describes how attacks manifest themselves. The cyber kill chain consists of seven (7) different stages.

<img width="2937" height="384" alt="image" src="https://github.com/user-attachments/assets/8ac149be-d546-4a4f-9549-24f2597a744d" />

1. Recon stage is the initial stage, and it involves the part where an attacker chooses their target. Additionally, the attacker then performs information gathering to become more familiar with the target and gathers as much useful data as possible, which can be used in not only this stage but also in other stages of this chain. Some attackers recon passively through social media and company websites. Job ads and company partners often reveal information about the technology utilized in the target organization. They can provide extremely specific information about antivirus tools, operating systems, and networking technologies. Other attackers go a step further; they start 'poking' and actively scan external web applications and IP addresses that belong to the target organization.

2. Weaponize stage, the malware to be used for initial access is developed and embedded into some type of exploit or deliverable payload. It is likely that the attacker has gathered information to identify the present antivirus or EDR technology in the target organization. On a large scale, the sole purpose of this initial stage is to provide remote access to a compromised machine in the target environment, which also has the capability to persist through machine reboots and the ability to deploy additional tools and functionality on demand.

3. Delivery stage, the exploit or payload is delivered to the victim(s). Traditional approaches are phishing emails that either contain a malicious attachment or a link to a web page. The web page can be twofold: either containing an exploit/hosting the malicious payload to avoid sending it through email scanning tools or an attempt to trick the victim into entering their credentials and collect them. It is extremely rare to deliver a payload that requires the victim to do more than double-click an executable file or a script. Some attackers call the victim on the phone with a social engineering pretext or physical interaction to deliver the payload via USB or other tools.

4. Exploitation stage is the moment when an exploit or a delivered payload is triggered. During the exploitation stage of the cyber kill chain, the attacker typically attempts to execute code on the target system in order to gain access or control.

5. Installation stage, the initial stager is executed and is running on the compromised machine. Some common techniques used in the installation stage include:
   - Droppers: Attackers may use droppers to deliver malware onto the target system. A dropper is a small piece of code that is designed to install malware on the system and execute it. The dropper may be delivered through various means, such as email attachments, malicious websites, or social engineering tactics.
   - Backdoors: A backdoor is a type of malware that is designed to provide the attacker with ongoing access to the compromised system. The backdoor may be installed by the attacker during the exploitation stage or delivered through a dropper.
   - Rootkits: A rootkit is a type of malware that is designed to hide its presence on a compromised system. Rootkits are often used in the installation stage to evade detection by antivirus software and other security tools. The rootkit may be installed by the attacker during the exploitation stage or delivered through a dropper.

6. Command and control stage, the attacker establishes a remote access capability to the compromised machine.
7. Action stage or objective of the attack. The objective of each attack can vary. Some adversaries may go after exfiltrating confidential data, while others may want to obtain the highest level of access possible within a network to deploy ransomware.

It is important to understand that adversaries won't operate in a linear manner (like the cyber kill chain shows). Some previous cyber kill chain stages will be repeated over and over again. If we take, for example, the installation stage of a successful compromise, the logical next step for an adversary going forward is to initiate the recon stage again to identify additional targets and find vulnerabilities to exploit. 

## Incident Handling Process Overview
