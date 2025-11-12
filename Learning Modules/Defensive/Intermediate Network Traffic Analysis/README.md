# Intermediate Network Traffic Analysis
Brief notes on the HackTheBox Acedemy learning module, Intermediate Network Traffic Analysis, for the SOC Analyst learning path.

### Download lab files
```
wget -O file.zip 'https://academy.hackthebox.com/storage/resources/pcap_files.zip' && mkdir tempdir && unzip file.zip -d tempdir && mkdir -p pcaps && mv tempdir/Intermediate_Network_Traffic_Analysis/* pcaps/ && rm -r tempdir file.zip
```

# Link Layer Attacks

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

# Detecting Network Abnormalities
## Fragmentation Attacks
1. Length - IP header length: This field contains the overall length of the IP header.
2. Total Length - IP Datagram/Packet Length: This field specifies the entire length of the IP packet, including any relevant data.
3. Fragment Offset: In many cases when a packet is large enough to be divided, the fragmentation offset will be set to provide instructions to reassemble the packet upon delivery to the destination host.
4. Source and Destination IP Addresses: These fields contain the origination (source) and destination IP addresses for the two communicating hosts.

### Commonly Abused Fields
Innately, attackers might craft these packets to cause communication issues. Traditionally, an attacker might attempt to evade IDS controls through packet malformation or modification. As such, diving into each one of these fields and understanding how we can detect their misuse will equip us with the tools to succeed in our traffic analysis efforts.

### Abuse of Fragmentation
Fragmentation serves as a means for our legitimate hosts to communicate large data sets to one another by splitting the packets and reassembling them upon delivery. This is commonly achieved through setting a maximum transmission unit (MTU). The MTU is used as the standard to divide these large packets into equal sizes to accommodate the entire transmission. It is worth noting that the last packet will likely be smaller. This field gives instructions to the destination host on how it can reassemble these packets in logical order.

Commonly, attackers might abuse this field for the following purposes:

1. IPS/IDS Evasion - Let's say for instance that our intrusion detection controls do not reassemble fragmented packets. Well, for short, an attacker could split their nmap or other enumeration techniques to be fragmented, and as such it could bypass these controls and be reassembled at the destination.
2. Firewall Evasion - Through fragmentation, an attacker could likewise evade a firewall's controls through fragmentation. Once again, if the firewall does not reassemble these packets before delivery to the destination host, the attacker's enumeration attempt might succeed.
3. Firewall/IPS/IDS Resource Exhaustion - Suppose an attacker were to craft their attack to fragment packets to a very small MTU (10, 15, 20, and so on), the network control might not reassemble these packets due to resource constraints, and the attacker might succeed in their enumeration efforts.
4. Denial of Service - For old hosts, an attacker might utilize fragmentation to send IP packets exceeding 65535 bytes through ping or other commands. In doing so, the destination host will reassemble this malicious packet and experience countless different issues. As such, the resultant condition is successful denial-of-service from the attacker.

### Finding Irregularities in Fragment Offsets
In order to better understand the abovementioned mechanics, we can open the related traffic capture file in Wireshark.
```
thossa00@htb[/htb]$ wireshark nmap_frag_fw_bypass.pcapng
```

For starters, we might notice several ICMP requests going to one host from another, this is indicative of the starting requests from a traditional Nmap scan. This is the beginning of the host discovery process. An attacker might run a command like this.
```
thossa00@htb[/htb]$ nmap <host ip>

# An attacker might define a maximum transmission unit size like this in order to fragment their port scanning packets.
thossa00@htb[/htb]$ nmap -f 10 <host ip>
```
In doing so they will generate IP packets with a maximum size of 10. Seeing a ton of fragmentation from a host can be an indicator of this attack, and it would look like the following.
```
Open Wireshark, and open nmap_frag_fw_bypass capture file
Filter for:
tcp.flags.reset == 1
This will return TCP packets that have the RST flag
Bottom left should show:
Packets: 266239 : Displayed: 66535
```

## IP Source & Destination Spoofing Attacks
We should always consider the following when analyzing these fields for our traffic analysis efforts:

- The Source IP Address should always be from our subnet - If we notice that an incoming packet has an IP source from outside of our local area network, this can be an indicator of packet crafting.
- The Source IP for outgoing traffic should always be from our subnet - If the source IP is from a different IP range than our own local area network, this can be an indicator of malicious traffic that is originating from inside our network.

An attacker might conduct these packet crafting attacks towards the source and destination IP addresses for many different reasons or desired outcomes. Here are a few that we can look for:

- Decoy Scanning - In an attempt to bypass firewall restrictions, an attacker might change the source IP of packets to enumerate further information about a host in another network segment. Through changing the source to something within the same subnet as the target host, the attacker might succeed in firewall evasion.
- Random Source Attack DDoS - Through random source crafting an attacker might be able to send tons of traffic to the same port on the victim host. This in many cases, is used to exhaust resources of our network controls or on the destination host.
- LAND Attacks - LAND Attacks operate similarly to Random Source denial-of-service attacks in the nature that the source address is set to the same as the destination hosts. In doing so the attacker might be able to exhaust network resources or cause crashes on the target host.
- SMURF Attacks - Similar to LAND and Random Source attacks, SMURF attacks work through the attacker sending large amounts of ICMP packets to many different hosts. However, in this case the source address is set to the victim machines, and all of the hosts which receive this ICMP packet respond with an ICMP reply causing resource exhaustion on the crafted source address (victim).
- Initialization Vector Generation - In older wireless networks such as wired equivalent privacy, an attacker might capture, decrypt, craft, and re-inject a packet with a modified source and destination IP address in order to generate initialization vectors to build a decryption table for a statistical attack. These can be seen in nature by noticing an excessive amount of repeated packets between hosts.

The attacks we will be exploring in this section derive from IP layer communications and not ARP poisoning.

### Finding Decoy Scanning Attempts
When an attacker wants to gather information, they might change their source address to be the same as another legitimate host, or in some cases entirely different from any real host. This is to attempt to evade IDS/Firewall controls, and it can be easily observed:

- Initial Fragmentation from a fake address
- Some TCP traffic from the legitimate source address

A simple way that we can prevent this attack beyond just detecting it through our traffic analysis efforts is the following:

- Have our IDS/IPS/Firewall act as the destination host would - In the sense that reconstructing the packets gives a clear indication of malicious activity.
- Watch for connections started by one host, and taken over by another - The attacker after all has to reveal their true source address in order to see that a port is open. This is strange behavior and we can define our rules to prevent it.

### Finding Random Source Attacks
Related PCAP File(s):

- ICMP_rand_source.pcapng - On the opposite side of things, we can begin to explore denial-of-service attacks through source and destination address spoofing. This can be done like the opposite of a SMURF attack, in which many hosts will ping one host which does not exist, and the pinged host will ping back all others and get no reply.
  
- ICMP_rand_source_larg_data.pcapng - We should also consider that attackers might fragment these random hosts communications in order to draw out more resource exhaustion.

- TCP_rand_source_attacks.pcapng - LAND attacks, these attacks will be used by attackers to exhaust resources to one specific service on a port. Instead of spoofing the source address to be the same as the destination, the attacker might randomize them.

### Finding Smurf Attacks
SMURF Attacks are a notable distributed denial-of-service attack, in the nature that they operate through causing random hosts to ping the victim host back:

- The attacker will send an ICMP request to live hosts with a spoofed address of the victim host
- The live hosts will respond to the legitimate victim host with an ICMP reply
- This may cause resource exhaustion on the victim host, sometimes attackers will include fragmentation and data on these ICMP requests to make the traffic volume larger.

### Finding LAND Attacks
LAND attacks operate through an attacker spoofing the source IP address to be the same as the destination. These denial-of-service attacks work through sheer volume of traffic and port re-use. Essentially, if all base ports are occupied, it makes real connections much more difficult to establish to our affected host.

## TCP Handshake Abnormalities
To initiate a TCP connection for whatever purpose the client first sends the machine it is attempting to connect to a TCP SYN request to begin the TCP connection.

If this port is open, and in fact able to be connected to, the machine responds with a TCP SYN/ACK to acknowledge that the connection is valid and able to be used. However, we should consider all TCP flags
|Flags|	Description
|:-:|:-:|
|URG (Urgent)|	This flag is to denote urgency with the current data in stream.
|ACK (Acknowledgement)|	This flag acknowledges receipt of data.
|PSH (Push)|	This flag instructs the TCP stack to immediately deliver the received data to the application layer, and bypass buffering.
|RST (Reset)|	This flag is used for termination of the TCP connection.
|SYN (Synchronize)|	This flag is used to establish an initial connection with TCP.
|FIN (Finish)|	This flag is used to denote the finish of a TCP connection. It is used when no more data needs to be sent.
|ECN (Explicit Congestion Notification)|	This flag is used to denote congestion within our network, it is to let the hosts know to avoid unnecessary re-transmissions.

When we are performing our traffic analysis efforts we can look for the following strange conditions:

- Too many flags of a kind or kinds - This could show us that scanning is occurring within our network.
- The usage of different and unusual flags - Sometimes this could indicate a TCP RST attack, hijacking, or simply some form of control evasion for scanning.
- Solo host to multiple ports, or solo host to multiple hosts - Easy enough, we can find scanning as we have done before by noticing where these connections are going from one host. In a lot of cases, we may even need to consider decoy scans and random source attacks.

## TCP Connection Resets & Hijacking
TCP does not provide the level of protection to prevent our hosts from having their connections terminated or hijacked by an attacker. As such, we might notice that a connection gets terminated by an RST packet, or hijacked through connection hijacking.

This attack is a combination of a few conditions:

- The attacker will spoof the source address to be the affected machine's
- The attacker will modify the TCP packet to contain the RST flag to terminate the connection
- The attacker will specify the destination port to be the same as one currently in use by one of our machines.

As such, we might notice an excessive amount of packets going to one port. One way we can verify that this is indeed a TCP RST attack is through the physical address of the transmitter of these TCP RST packets. Suppose, the IP address 192.168.10.4 is registered to aa:aa:aa:aa:aa:aa in our network device list, and we notice an entirely different MAC sending these. However, it is worth noting that an attacker might spoof their MAC address in order to further evade detection. In this case, we could notice retransmissions and other issues.

### TCP Connection Hijacking
In this case the attacker will actively monitor the target connection they want to hijack.

The attacker will then conduct sequence number prediction in order to inject their malicious packets in the correct order. During this injection they will spoof the source address to be the same as our affected machine.

The attacker will need to block ACKs from reaching the affected machine in order to continue the hijacking. They do this either through delaying or blocking the ACK packets. As such, this attack is very commonly employed with ARP poisoning, and we might notice the following in our traffic analysis.

<img width="300" height="50" alt="image" src="https://github.com/user-attachments/assets/89a7c484-0522-433f-b3ce-54abeb5cbe3d" />


## ICMP Tunneling
Tunneling is a technique employed by adversaries in order to exfiltrate data from one location to another. In many cases, we might notice this through the attacker possessing some command and control over one of our machines. One of the more common types is SSH tunneling. However, proxy-based, HTTP, HTTPs, DNS, and other types can be observed in similar ways.

In the case of ICMP tunneling an attacker will append data they want to exfiltrate to the outside world or another host in the data field in an ICMP request. This is done with the intention to hide this data among a common protocol type like ICMP, and hopefully get lost within our network traffic.

Since ICMP tunneling is primarily done through an attacker adding data into the data field for ICMP, we can find it by looking at the contents of data per request and reply.

We can filter our wireshark capture to only ICMP requests and replies by entering ICMP into the filter bar. Normal ICMP requests send 48 bytes. However a malicious packet would have a larger size. We can look on the right side of our screen in Wireshark. In this case, we might notice something like a Username and Password being pinged to an external or internal host. This is a direct indication of ICMP tunneling.

On the other hand, more advanced adversaries will utilize encoding or encryption when transmitting exfiltrated data, even in the case of ICMP tunneling. We could copy this value out of Wireshark and decode it within linux with the base64 utility.

```
thossa00@htb[/htb]$ echo 'VGhpcyBpcyBhIHNlY3VyZSBrZXk6IEtleTEyMzQ1Njc4OQo=' | base64 -d
```

### Preventing ICMP Tunneling

- Block ICMP Requests - Simply, if ICMP is not allowed, attackers will not be able to utilize it.
- Inspect ICMP Requests and Replies for Data - Stripping data, or inspecting data for malicious content on these requests and replies can allow us better insight into our environment, and the ability to prevent this data exfiltration.

# Application Layer Attacks
## HTTP/HTTPs Service Enumeration

Many times, we might notice strange traffic to our web servers. In one of these cases, we might see that one host is generating excessive traffic with HTTP or HTTPs. Attackers like to abuse the transport layer many times, as the applications running on our servers might be vulnerable to different attacks.

We can detect and identify fuzzing attempts through the following:

- Excessive HTTP/HTTPs traffic from one host
- Referencing our web server's access logs for the same behavior

Attackers will attempt to fuzz our server to gather information before attempting to launch an attack. We might already have a Web Application Firewall in place to prevent this.

### Finding Directory Fuzzing
Directory fuzzing is used by attackers to find all possible web pages and locations in our web applications. We can find this during our traffic analysis by limiting our Wireshark view to only http traffic.

Secondarily, if we wanted to remove the responses from our server, we could simply specify http.request

Detect directory fuzzing:

- A host will repeatedly attempt to access files on our web server which do not exist (response 404).
- A host will send these in rapid succession.

We can also always reference this traffic within our access logs on our web server. For Apache this would look like the following two examples. To use grep, we could filter like so:

```
thossa00@htb[/htb]$ cat access.log | grep "192.168.10.5"

192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /randomfile1 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /frand2 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bash_history HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bashrc HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cache HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.config HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cvs HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
```

### Finding Other Fuzzing Techniques
Some of these could include fuzzing dynamic or static elements of our web pages such as id fields. Or in some other cases, the attacker might look for IDOR vulnerabilities in our site, especially if we are handling json parsing (changing return=max to return=min).

To limit traffic to just one host, use the following filter:

http.request and ((ip.src_host == <suspected IP>) or (ip.dst_host == <suspected IP>))

Sometimes attackers will do the following to prevent detection

- Stagger these responses across a longer period of time.
- Send these responses from multiple hosts or source addresses.

### Preventing Fuzzing Attempts
- Maintain our virtualhost or web access configurations to return the proper response codes to throw off these scanners.
- Establish rules to prohibit these IP addresses from accessing our server through our web application firewall.

## Strange HTTP Headers

We might not notice anything like fuzzing right away when analyzing our web server's traffic. However, this does not always indicate that nothing bad is happening. Instead, we can always look a little bit deeper. In order to do so, we might look for strange behavior among HTTP requests. Some of which are weird headers like:

- Weird Hosts (Host: )
- Unusual HTTP Verbs
- Changed User Agents

We can find any irregular Host headers with the following command. We specify our web server's real IP address to exclude any entries which use this real header. If we were to do this for an external web server, we could specify the domain name here.

http.request and (!(http.host == "192.168.10.7"))

Attackers will attempt to use different host headers to gain levels of access they would not normally achieve through the legitimate host. They may use proxy tools like burp suite or others to modify these before sending them to the server. In order to prevent successful exploitation beyond only detecting these events, we should always do the following:

- Ensure that our virtualhosts or access configurations are setup correctly to prevent this form of access.
- Ensure that our web server is up to date.

### Analyzing Code 400s and Request Smuggling
We might also notice some bad responses from our web server, like code 400s. These codes indicate a bad request from the client, so they can be a good place to start when detecting malicious actions via http/https. In order to filter for these, we can use the following:

http.response.code == 400

HTTP request smuggling or CRLF (Carriage Return Line Feed). Essentially, an attacker will try the following:

```
GET%20%2flogin.php%3fid%3d1%20HTTP%2f1.1%0d%0aHost%3a%20192.168.10.5%0d%0a%0d%0aGET%20%2fuploads%2fcmd2.php%20HTTP%2f1.1%0d%0aHost%3a%20127.0.0.1%3a8080%0d%0a%0d%0a%20HTTP%2f1.1 Host: 192.168.10.5
```

Which will be decoded by our server like this:

```
GET /login.php?id=1 HTTP/1.1
Host: 192.168.10.5

GET /uploads/cmd2.php HTTP/1.1
Host: 127.0.0.1:8080

 HTTP/1.1
Host: 192.168.10.5
```

In cases where our configurations are vulnerable, the first request will go through, and the second request will as well shortly after. This can give an attacker levels of access that we would normally prohibit.

Code 400s can give clear indication to adversarial actions during our traffic analysis efforts. Additionally, we would notice if an attacker is successful with this attack by finding the code 200 (success) in response to one of the requests which look like this.

## Cross-Site Scripting (XSS) & Code Injection Detection
Suppose we were looking through our HTTP requests and noticed that a good amount of requests were being sent to an internal "server," we did not recognize. This could be a clear indication of cross-site scripting.

Cross-site scripting works through an attacker injecting malicious javascript or script code into one of our web pages through user input. When other users visit our web server their browsers will execute this code. Attackers in many cases will utilize this technique to steal tokens, cookies, session values, and more. 

### Preventing XSS and Code Injection

- Sanitize and handle user input in an acceptable manner.
- Do not interpret user input as code.

## SSL Renegotiation Attacks
### HTTPs Breakdown
Unlike HTTP, which is a stateless protocol, HTTPs incorporates encryption to provide security for web servers and clients. It does so with the following.

- Transport Layer Security (Transport Layer Security)
- Secure Sockets Layer (SSL)

When a client establishes a HTTPs connection with a server, it conducts the following:

1. Client Hello - The initial step is for the client to send its hello message to the server. This message contains information like what TLS/SSL versions are supported by the client, a list of cipher suites (aka encryption algorithms), and random data (nonces) to be used in the following steps.
2. Server Hello - Responding to the client Hello, the server will send a Server Hello message. This message includes the server's chosen TLS/SSL version, its selected cipher suite from the client's choices, and an additional nonce.
3. Certificate Exchange - The server then sends its digital certificate to the client, proving its identity. This certificate includes the server's public key, which the client will use to conduct the key exchange process.
4. Key Exchange - The client then generates what is referred to as the premaster secret. It then encrypts this secret using the server's public key from the certificate and sends it on to the server.
5. Session Key Derivation - Then both the client and the server use the nonces exchanged in the first two steps, along with the premaster secret to compute the session keys. These session keys are used for symmetric encryption and decryption of data during the secure connection.
6. Finished Messages - In order to verify the handshake is completed and successful, and also that both parties have derived the same session keys, the client and server exchange finished messages. This message contains the hash of all previous handshake messages and is encrypted using the session keys.
7. Secure Data Exchange - Now that the handshake is complete, the client and the server can now exchange data over the encrypted channel.

As such, one of the more common HTTPs based attacks are SSL renegotiation, in which an attacker will negotiate the session to the lowest possible encryption standard.

### Diving into SSL Renegotiation Attacks
In order to filter to only handshake messages we can use this filter in Wireshark:

ssl.record.content_type == 22

The content type 22 specifies handshake messages only. 

```
_ws.col.info == "Client Hello"
```

When we are looking for SSL renegotiation attacks, we can look for the following.

- Multiple Client Hellos - This is the most obvious sign of an SSL renegotiation attack. We will notice multiple client hellos from one client within a short period like above. The attacker repeats this message to trigger renegotiation and hopefully get a lower cipher suite.
- Out of Order Handshake Messages - Simply put, sometimes we will see some out of order traffic due to packet loss and others, but in the case of SSL renegotiation some obvious signs would be the server receiving a client hello after completion of the handshake.

An attacker might conduct this attack against us for the following reasons

- Denial of Service - SSL renegotiation attacks consume a ton of resources on the server side, and as such it might overwhelm the server and cause it to be unresponsive.
- SSL/TLS Weakness Exploitation - The attacker might attempt renegotiation to potentially exploit vulnerabilities with our current implementation of cipher suites.
- Cryptanalysis - The attacker might use renegotiation as a part of an overall strategy to analyze our SSL/TLS patterns for other systems.

## Peculiar DNS Traffic

When a client initiates a DNS forward lookup query, it does the following steps:

|Step|	Description
|:-:|:-:|
|1. Query Initiation|	When the user wants to visit something like academy.hackthebox.com it initiates a DNS forward query.
|2. Local Cache Check|	The client then checks its local DNS cache to see if it has already resolved the domain name to an IP address. If not it continues with the following.
|3. Recursive Query|	The client then sends its recursive query to its configured DNS server (local or remote).
|4. Root Servers|	The DNS resolver, if necessary, starts by querying the root name servers to find the authoritative name servers for the top-level domain (TLD). There are 13 root servers distributed worldwide.
|5. TLD Servers|	The root server then responds with the authoritative name servers for the TLD (aka .com or .org)
|6. Authoritative Servers|	The DNS resolver then queries the TLD's authoritative name servers for the second-level domain (aka hackthebox.com).
|7. Domain Name's Authoritative Servers|	Finally, the DNS resolver queries the domains authoritative name servers to obtain the IP address associated with the requested domain name (aka academy.hackthebox.com).
|8. Response|	The DNS resolver then receives the IP address (A or AAAA record) and sends it back to the client that initiated the query.

### DNS Reverse Lookups/Queries
On the opposite side, we have Reverse Lookups. These occur when a client already knows the IP address and wants to find the corresponding FQDN (Fully Qualified Domain Name):

|Step|	Description|
|:-:|:-:|
|1. Query Initiation|	The client sends a DNS reverse query to its configured DNS resolver (server) with the IP address it wants to find the domain name.
|2. Reverse Lookup Zones|	The DNS resolver checks if it is authoritative for the reverse lookup zone that corresponds to the IP range as determined by the received IP address. Aka 192.0.2.1, the reverse zone would be 1.2.0.192.in-addr.arpa
|3. PTR Record Query|	The DNS resolver then looks for a PTR record on the reverse lookup zone that corresponds to the provided IP address.
|4. Response|	If a matching PTR is found, the DNS server (resolver) then returns the FQDN of the IP for the client.

<img width="837" height="410" alt="image" src="https://github.com/user-attachments/assets/a315f1c0-b644-4de4-a130-ee8bde468a09" />

### DNS Record Types

|Record Type|	Description
|:-:|:-:|
|A (Address)|	This record maps a domain name to an IPv4 address
|AAAA (Ipv6 Address)|	This record maps a domain name to an IPv6 address
|CNAME (Canonical Name)|	This record creates an alias for the domain name. Aka hello.com = world.com
|MX (Mail Exchange)|	This record specifies the mail server responsible for receiving email messages on behalf of the domain.
|NS (Name Server)|	This specifies an authoritative name servers for a domain.
|PTR (Pointer)|	This is used in reverse queries to map an IP to a domain name
|TXT (Text)|	This is used to specify text associated with the domain
|SOA (Start of Authority)|	This contains administrative information about the zone

### Finding DNS Enumeration Attempts
We might notice a significant amount of DNS traffic from one host when we start to look at our raw output in Wireshark. We might even notice this traffic concluded with something like ANY:

<img width="971" height="71" alt="image" src="https://github.com/user-attachments/assets/de211996-e8c3-4dc8-804d-9f6d8accf0db" />

### Finding DNS Tunneling
On the other hand, we might notice a good amount of text records from one host. This could indicate DNS tunneling. Like ICMP tunneling, attackers can and have utilized DNS forward and reverse lookup queries to perform data exfiltration. They do so by appending the data they would like to exfiltrate as a part of the TXT field. DNS Tunnelling can be read through WireShark captures, however, this data might be encoded or encrypted.

We can retrieve this value from wireshark by locating it and right-clicking the value to specify to copy it. Then if we were to go into our Linux machine, in this case we could utilize something like base64 -d to retrieve the true value.

```
thossa00@htb[/htb]$ echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d 

U0ZSQ2UxZHZkV3hrWDNsdmRWOW1iM0ozWVhKa1gyMWxYM1JvYVhOZmNISmxkSFI1WDNCc1pXRnpaWDBLCg==
```

However, in some cases attackers will double if not triple encode the value they are attempting to exfiltrate through DNS tunneling, so we might need to do the following.

```
thossa00@htb[/htb]$ echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d | base64 -d | base64 -d
```

However, we might need to do more than just base64 decode these values, as in many cases as mentioned these values might be encrypted.

Attackers might conduct DNS tunneling for the following reasons:

|Step|	Description
|:-:|:-:|
|1. Data Exfiltration|	As shown above DNS tunneling can be helpful for attackers trying to get data out of our network without getting caught.
|2. Command and Control|	Some malware and malicious agents will utilize DNS tunneling on compromised systems in order to communicate back to their command and control servers. Notably, we might see this method of usage in botnets.
|3. Bypassing Firewalls and Proxies|	DNS tunneling allows attackers to bypass firewalls and web proxies that only monitor HTTP/HTTPs traffic. DNS traffic is traditionally allowed to pass through network boundaries. As such, it is important that we monitor and control this traffic.
|4. Domain Generation Algorithms (DGAs)|	Some more advanced malware will utilize DNS tunnels to communicate back to their command and control servers that use dynamically generated domain names through DGAs. This makes it much more difficult for us to detect and block these domain names.

### Strange Telnet & UDP Connections
In many older cases, such as our Windows NT like machines, they may still utilize telnet to provide remote command and control to microsoft terminal services. Telnet traffic tends to be decrypted and easily inspectable, but like ICMP, DNS, and other tunneling methods, attackers may encrypt, encode, or obfuscate this text.

### Unrecognized TCP Telnet in Wireshark
Telnet is just a communication protocol, and as such can be easily switched from port 23 to another port by an attacker. Keeping an eye on these strange port communications can allow us to find potentially malicious actions.

We can inspect the contents of these packets through their data field, or by following the TCP stream.
### Telnet Protocol through IPv6
We can narrow down our filter in Wireshark to only show telnet traffic from these addresses with the following filter.

((ipv6.src_host == fe80::c9c8:ed3:1b10:f10b) or (ipv6.dst_host == fe80::c9c8:ed3:1b10:f10b)) and telnet

### Watching UDP Communications
On the other hand, attackers might opt to use UDP connections over TCP in their exfiltration efforts. Like TCP, we can follow UDP traffic in Wireshark, and inspect its contents through the udp stream feature.

UDP although less reliable than TCP provides quicker connections through its connectionless state. As such, we might find legitimate traffic that uses UDP like the following:

|Step|	Description
|:-:|:-:|
|1. Real-time Applications|	Applications like streaming media, online gaming, real-time voice and video communications
|2. DNS (Domain Name System)|	DNS queries and responses use UDP
|3. DHCP (Dynamic Host Configuration Protocol)|	DHCP uses UDP to assign IP addresses and configuration information to network devices.
|4. SNMP (Simple Network Management Protocol)|	SNMP uses UDP for network monitoring and management
|5. TFTP (Trivial File Transfer Protocol)|	TFTP uses UDP for simple file transfers, commonly used by older Windows systems and others.
