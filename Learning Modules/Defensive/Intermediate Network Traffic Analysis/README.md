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
Some typical red flags indicative of ARP scanning are:
1. Broadcast ARP requests sent to sequential IP addresses (.1,.2,.3,...)
2. Broadcast ARP requests sent to non-existent hosts
3. Potentially, an unusual volume of ARP traffic originating from a malicious or compromised host

### Finding ARP Scanning
If we were to open the related traffic capture file (ARP_Scan.pcapng) in Wireshark and apply the filter arp.opcode, we might observe the following:

<img width="927" height="345" alt="image" src="https://github.com/user-attachments/assets/3507ef06-08ca-4381-8b6a-b9f510e19b85" />

ARP requests are being propagated by a single host to all IP addresses in a sequential manner. This pattern is symptomatic of ARP scanning and is a common feature of widely-used scanners such as Nmap. Furthermore, we may discern that active hosts respond to these requests via their ARP replies. This could signal the successful execution of the information-gathering tactic by the attacker.

### Identifying Denial-of-Service
An attacker can exploit ARP scanning to compile a list of live hosts. Upon acquiring this list, the attacker might alter their strategy to deny service to all these machines. Essentially, they will strive to contaminate an entire subnet and manipulate as many ARP caches as possible. 

We may witness the duplicate allocation of 192.168.10.1 to client devices. This indicates that the attacker is attempting to corrupt the ARP cache of these victim devices with the intention of obstructing traffic in both directions.

### Responding To ARP Attacks
1. Tracing and Identification: First and foremost, the attacker's machine is a physical entity located somewhere. If we manage to locate it, we could potentially halt its activities. On occasions, we might discover that the machine orchestrating the attack is itself compromised and under remote control.
2. Containment: To stymie any further exfiltration of information by the attacker, we might contemplate disconnecting or isolating the impacted area at the switch or router level. This action could effectively terminate a DoS or MITM attack at its source.

Link layer attacks often fly under the radar. While they may seem insignificant to identify and investigate, their detection could be pivotal in preventing the exfiltration of data from higher layers of the OSI model.

## 802.11 Denial of Service
### Capturing 802.11 Traffic
To examine our 802.11 raw traffic, we would require a WIDS/WIPS system or a wireless interface equipped with monitor mode. Similar to promiscuous mode in Wireshark, monitor mode permits us to view raw 802.11 frames and other packet types which might otherwise remain invisible.
Let's assume we do possess a Wi-Fi interface capable of monitor mode. We could enumerate our wireless interfaces in Linux using the following command:
```
thossa00@htb[/htb]$ iwconfig
```

We have a couple of options to set our interface into monitor mode. Firstly, employing airodump-ng, we can use the ensuing command:
```
thossa00@htb[/htb]$ sudo airmon-ng start wlan0
```
Secondly, using system utilities, we would need to deactivate our interface, modify its mode, and then reactivate it.
```
thossa00@htb[/htb]$ sudo ifconfig wlan0 down
thossa00@htb[/htb]$ sudo iwconfig wlan0 mode monitor
thossa00@htb[/htb]$ sudo ifconfig wlan0 up
```
We could verify if our interface is in monitor mode using the iwconfig utility.
```
thossa00@htb[/htb]$ iwconfig
```

To commence capturing traffic from our clients and network, we can employ airodump-ng. We need to specify our AP's channel with -c, its BSSID with --bssid, and the output file name with -w.
```
thossa00@htb[/htb]$ sudo airodump-ng -c 4 --bssid F8:14:FE:4D:E6:F1 wlan0 -w raw
```

### How Deauthentication Attacks Work
Among the more frequent attacks we might witness or detect is a deauthentication/dissociation attack. This is a commonplace link-layer precursor attack that adversaries might employ for several reasons:

1. To capture the WPA handshake to perform an offline dictionary attack
2. To cause general denial of service conditions
3. To enforce users to disconnect from our network, and potentially join their network to retrieve information

The attacker will fabricate an 802.11 deauthentication frame pretending it originates from our legitimate access point. By doing so, the attacker might manage to disconnect one of our clients from the network. Often, the client will reconnect and go through the handshake process while the attacker is sniffing.

This attack operates by the attacker spoofing or altering the MAC of the frame's sender. The client device cannot really discern the difference without additional controls like IEEE 802.11w (Management Frame Protection). Each deauthentication request is associated with a reason code explaining why the client is being disconnected.

In most scenarios, basic tools like aireplay-ng and mdk4 employ reason code 7 for deauthentication.

### Finding Deauthentication Attacks
If we wanted to limit our view to traffic from our AP's BSSID (MAC), we could use the following Wireshark filter:
```
wlan.bssid == xx:xx:xx:xx:xx:xx
```
Suppose we wanted to take a look at the deauthentication frames from our BSSID or an attacker pretending to send these from our BSSID, we could use the following Wireshark filter:
```
(wlan.bssid == xx:xx:xx:xx:xx:xx) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12)
```
With this filter, we specify the type of frame (management) with 00 and the subtype (deauthentication) with 12. We might notice right away that an excessive amount of deauthentication frames were sent to one of our client devices. This would be an immediate indicator of this attack. Additionally, if we were to open the fixed parameters under wireless management, we might notice that reason code 7 was utilized.

As mentioned, aireplay-ng and mdk4, which are common attack tools, utilize this reason code by default. We could do with the following wireshark filter:
```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 7)
```
### Revolving Reason Codes
Alternatively, a more sophisticated actor might attempt to evade this innately obvious sign by revolving reason codes. The principle to this, is that an attacker might try to evade any alarms that they could set off with a wireless intrusion detection system by changing the reason code every so often.

The trick to this technique of detection is incrementing like an attacker script would. We would first start with reason code 1.
```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 1)
```
Then we would shift over to reason code 2.
```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 2)
```
We would continue this sequence.
```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 3)
```

As such, deauthentication can be a pain to deal with, but we have some compensating measures that we can implement to prevent this from occuring in the modern day and age. These are:

1. Enable IEEE 802.11w (Management Frame Protection) if possible
2. Utilize WPA3-SAE
3. Modify our WIDS/WIPS detection rules

### Finding Failed Authentication Attempts
Suppose an attacker was to attempt to connect to our wireless network. We might notice an excessive amount of association requests coming from one device. To filter for these we could use the following.
```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 0) or (wlan.fc.type_subtype == 1) or (wlan.fc.type_subtype == 11)
```

## Rogue Access Point & Evil-Twin Attacks
### Airodump-ng Detection
We could utilize the ESSID filter for Airodump-ng to detect Evil-Twin style access points.
```
thossa00@htb[/htb]$ sudo airodump-ng -c 4 --essid HTB-Wireless wlan0 -w raw
```
The above example would show that in fact an attacker might have spun up an open access point that has an identical ESSID as our access point. An attacker might do this to host what is commonly referred to as a hostile portal attack.

To conclusively ascertain whether this is an anomaly or an Airodump-ng error, filter for beacon frames, we could use the following.
```
(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)
```
Beacon analysis is crucial in differentiating between genuine and fraudulent access points. One of the initial places to start is the Robust Security Network (RSN) information. This data communicates valuable information to clients about the supported ciphers, among other things.

Suppose we wish to examine our legitimate access point's RSN information.

<img width="731" height="425" alt="image" src="https://github.com/user-attachments/assets/c5ae306c-2da2-46e8-bc5b-fe3ba829a9c5" />

It would indicate that WPA2 is supported with AES and TKIP with PSK as its authentication mechanism. However, when we switch to the illegitimate access point's RSN information, we may find it conspicuously missing.

<img width="622" height="211" alt="image" src="https://github.com/user-attachments/assets/581272ce-4a76-4749-b0ee-3e93b4397740" />

In most instances, a standard evil-twin attack will exhibit this characteristic. Nevertheless, we should always probe additional fields for discrepancies. For example, an attacker might employ the same cipher that our access point uses, making the detection of this attack more challenging. Under such circumstances, we could explore other aspects of the beacon frame, such as vendor-specific information, which is likely absent from the attacker's access point.

### Finding a Fallen User
To filter exclusively for the evil-twin access point, we would employ the following filter.
```
(wlan.bssid == F8:14:FE:4D:E6:F2)
```
If we detect ARP requests emanating from a client device connected to the suspicious network, we would identify this as a potential compromise indicator. In such instances, we should record pertinent details about the client device to further our incident response efforts.

- Its MAC address
- Its host name

### Finding Rogue Access Points
On the other hand, detecting rogue access points can often be a simple task of checking our network device lists. In the case of hotspot-based rogue access points (such as Windows hotspots), we might scrutinize wireless networks in our immediate vicinity. If we encounter an unrecognizable wireless network with a strong signal, particularly if it lacks encryption, this could indicate that a user has established a rogue access point to navigate around our perimeter controls.


## Fragmentation Attacks
