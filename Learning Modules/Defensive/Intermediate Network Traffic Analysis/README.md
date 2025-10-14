# Intermediate Network Traffic Analysis
Brief notes on the HackTheBox Acedemy learning module, Intermediate Network Traffic Analysis, for the SOC Analyst learning path.

### Download lab files
```
wget -O file.zip 'https://academy.hackthebox.com/storage/resources/pcap_files.zip' && mkdir tempdir && unzip file.zip -d tempdir && mkdir -p pcaps && mv tempdir/Intermediate_Network_Traffic_Analysis/* pcaps/ && rm -r tempdir file.zip
```

## ARP Spoofing & Abnormality Detection
The Address Resolution Protocol (ARP) has been a longstanding utility exploited by attackers to launch man-in-the-middle and denial-of-service attacks, among others.

### ARP Poisoning & Spoofing
Detecting these attacks can be challenging, as they mimic the communication structure of standard ARP traffic. Yet, certain ARP requests and replies can reveal their nefarious nature. 

1. 	Consider a network with three machines: the victim's computer, the router, and the attacker's machine.
2.	The attacker initiates their ARP cache poisoning scheme by dispatching counterfeit ARP messages to both the victim's computer and the router.
3.	The message to the victim's computer asserts that the gateway's (router's) IP address corresponds to the physical address of the attacker's machine.
4.	Conversely, the message to the router claims that the IP address of the victim's machine maps to the physical address of the attacker's machine.
5.	On successfully executing these requests, the attacker may manage to corrupt the ARP cache on both the victim's machine and the router, causing all data to be misdirected to the attacker's machine.
6.	If the attacker configures traffic forwarding, they can escalate the situation from a denial-of-service to a man-in-the-middle attack.
7.	By examining other layers of our network model, we might discover additional attacks. The attacker could conduct DNS spoofing to redirect web requests to a bogus site or perform SSL stripping to attempt the interception of sensitive data in transit.

We could potentially fend off these attacks with controls such as:

1. Static ARP Entries: By disallowing easy rewrites and poisoning of the ARP cache, we can stymie these attacks. This, however, necessitates increased maintenance and oversight in our network environment.
2. Switch and Router Port Security: Implementing network profile controls and other measures can ensure that only authorized devices can connect to specific ports on our network devices, effectively blocking machines attempting ARP spoofing/poisoning.

### Finding ARP Spoofing

Once we've navigated to Wireshark, we can streamline our view to focus solely on ARP requests and replies by employing the filter arp.opcode.

1. Opcode == 1: This represents all types of ARP Requests
2. Opcode == 2: This signifies all types of ARP Replies

To sift through more duplicate records, we can utilize the subsequent Wireshark filter.
```
arp.duplicate-address-detected && arp.opcode == 2
(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))
eth.addr == 50:eb:f6:ec:0e:7f or eth.addr == 08:00:27:53:0c:ba

arp.opcode == 1 && eth.src == 08:00:27:53:0c:ba
```

## ARP Scanning & Denial-of-Service
