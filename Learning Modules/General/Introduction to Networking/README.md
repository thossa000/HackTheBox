# Introduction to Networking
Brief notes written to review the material in the HackTheBox module, Intro to Networking.
## Network Types

|Network Type|Description|
|:-:|:-:|
|Wide Area Network (WAN)	|Internet|
|Local Area Network (LAN)	|Internal Networks (Ex: Home or Office)|
|Wireless Local Area Network (WLAN)	|Internal Networks accessible over Wi-Fi|
|Virtual Private Network (VPN)	|Connects multiple network sites to one LAN|
|Global Area Network (GAN)	|Global network (the Internet)|
|Metropolitan Area Network (MAN)	|Regional network (multiple LANs)|
|Wireless Personal Area Network (WPAN)	|Personal network (Bluetooth)|

## Network Topologies
### Connections
|Wired connections|Wireless connections|
|:-:|:-:|
|Coaxial cabling	|Wi-Fi|
|Glass fiber cabling	|Cellular|
|Twisted-pair cabling	|Satellite|

## Proxies
A proxy is when a device or service sits in the middle of a connection and acts as a mediator, inspecting traffic passing between the host and target. Without the ability to be a mediator, the device is technically a gateway, not a proxy. Proxies will almost always operate at Layer 7 of the OSI Model. 

There are many types of proxy services, but the key ones are:

- Dedicated Proxy / Forward Proxy - When a client makes a request to a computer, and that computer carries out the request. Often used in corporate networks, adding a layer of defense when browsing the web.
- Reverse Proxy - Instead of being designed to filter outgoing requests, it filters incoming ones. The most common goal with a Reverse Proxy, is to listen on an address and forward it to a closed-off network. ex. CloudFlare to defend against DDOS attacks.
- Transparent Proxy -  Intercepts the client's communication requests to the Internet and acts as a substitute instance. To the outside, the transparent proxy, like the non-transparent proxy, acts as a communication partner.

## Network Models
### OSI Model
The term OSI stands for Open Systems Interconnection model. OSI is a communication gateway between the network and end-users. The reference model has seven individual layers, each with clearly separated tasks.

|Layer|Function|
|:-:|:-:|
|7.Application	|Among other things, this layer controls the input and output of data and provides the application functions.|
|6.Presentation	|The presentation layer's task is to transfer the system-dependent presentation of data into a form independent of the application.|
|5.Session	|The session layer controls the logical connection between two systems and prevents, for example, connection breakdowns or other problems.|
|4.Transport	|Layer 4 is used for end-to-end control of the transferred data. The Transport Layer can detect and avoid congestion situations and segment data streams.|
|3.Network	|On the networking layer, connections are established in circuit-switched networks, and data packets are forwarded in packet-switched networks. Data is transmitted over the entire network from the sender to the receiver.|
|2.Data Link	|The central task of layer 2 is to enable reliable and error-free transmissions on the respective medium. For this purpose, the bitstreams from layer 1 are divided into blocks or frames.|
|1.Physical |The transmission techniques used are, for example, electrical signals, optical signals, or electromagnetic waves. Through layer 1, the transmission takes place on wired or wireless transmission lines.|
### TCP/IP Model
TCP/IP (Transmission Control Protocol/Internet Protocol) is a communication protocol that allows hosts to connect to the Internet. The Internet is entirely based on the TCP/IP protocol family. The protocols are responsible for the switching and transport of data packets on the Internet.

|Layer|Function|
|:-:|:-:|
|4.Application	|The Application Layer allows applications to access the other layers' services and defines the protocols applications use to exchange data.|
|3.Transport	|The Transport Layer is responsible for providing (TCP) session and (UDP) datagram services for the Application Layer.|
|2.Internet	|The Internet Layer is responsible for host addressing, packaging, and routing functions.|
|1.Link	|The Link layer is responsible for placing the TCP/IP packets on the network medium and receiving corresponding packets from the network medium. TCP/IP is designed to work independently of the network access method, frame format, and medium.|

![image](https://github.com/user-attachments/assets/d745d44a-c5a8-42b4-89cf-882c31685155)

## Adressing
### Network Layer
The network layer (Layer 3) of OSI controls the exchange of data packets, as these cannot be directly routed to the receiver and therefore have to be provided with routing nodes.  There is usually no processing of the data in the layers above the L3 in the nodes. Based on the addresses, the routing and the construction of routing tables are done.

The networking layer provides logical addressing, and routing function.
The most used protocals in this layer are:

- IPv4 / IPv6
- IPsec
- ICMP
- IGMP
- RIP
- OSPF

IPv4 addresses are structured in binary and decimal. Organized into 4 octects, each octect can have a value up to 255. IP addresses are sorted into 5 classes. 

MAC is the physical address for our network interfaces. Each host in a network has its own 48-bit (6 octets) Media Access Control (MAC) address, represented in hexadecimal format.Each physical device used by a host to connect has its own MAC address (Bluetooh, WLAN adapter, network card). The MAC address consists of a total of 6 bytes. The first half (3 bytes / 24 bit) is the so-called Organization Unique Identifier (OUI) defined by the Institute of Electrical and Electronics Engineers (IEEE) for the respective manufacturers. The last half of the MAC address is called the Individual Address Part or Network Interface Controller (NIC), which the manufacturers assign. The manufacturer sets this bit sequence only once and thus ensures that the complete address is unique.

When an IP packet is delivered, it must be addressed on layer 2 to the destination host's physical address or to the router / NAT, which is responsible for routing. Each packet has a sender address and a destination address. Address Resolution Protocol (ARP) is used in IPv4 to determine the MAC addresses associated with the IP addresses.

There exist several attack vectors that can potentially be exploited through the use of MAC addresses:
- MAC spoofing: This involves altering the MAC address of a device to match that of another device, typically to gain unauthorized access to a network.
- MAC flooding: This involves sending many packets with different MAC addresses to a network switch, causing it to reach its MAC address table capacity and effectively preventing it from functioning correctly.
- MAC address filtering: Some networks may be configured only to allow access to devices with specific MAC addresses that we could potentially exploit by attempting to gain access to the network using a spoofed MAC address.
- ARP spoofing: also known as ARP cache poisoning or ARP poison routing, is an attack that can be done using tools like Ettercap or Cain & Abel in which we send falsified ARP messages over a LAN. The goal is to associate our MAC address with the IP address of a legitimate device on the company's network, effectively allowing us to intercept traffic intended for the legitimate device.

### IPv6
IPv6 is the successsor to IPv4. IPv6 address is 128 bit long. The prefix identifies the host and network parts. 

|Features|IPv4|IPv6|
|:-:|:-:|:-:|
|Bit length|	32-bit|	128 bit|
|OSI layer|	Network Layer|	Network Layer|
|Adressing range|	~ 4.3 billion|	~ 340 undecillion|
|Representation|	Binary|	Hexadecimal|
|Prefix notation|	10.10.10.0/24|	fe80::dd80:b1a9:6687:2d3b/64|
|Dynamic addressing|	DHCP|	SLAAC / DHCPv6|
|IPsec|	Optional|	Mandatory|

## Protocols and Terminology
### Common Protocols

|Protocol|Acronym|Description|
|:-:|:-:|:-:|
|Wired Equivalent Privacy|	WEP|	WEP is a type of security protocol that was commonly used to secure wireless networks.|
|Secure Shell|	SSH|	A secure network protocol used to log into and execute commands on a remote system.|
|File Transfer Protocol|	FTP|	A network protocol used to transfer files from one system to another.|
|Simple Mail Transfer Protocol|	SMTP|	A protocol used to send and receive emails.|
|Hypertext Transfer Protocol|	HTTP|	A client-server protocol used to send and receive data over the internet.|
|Server Message Block|	SMB|	A protocol used to share files, printers, and other resources in a network.|
|Network File System|	NFS|	A protocol used to access files over a network.|
|Simple Network Management Protocol|	SNMP|	A protocol used to manage network devices.|
|Wi-Fi Protected Access|	WPA|	WPA is a wireless security protocol that uses a password to protect wireless networks from unauthorized access.|
|Temporal Key Integrity Protocol|	TKIP|	TKIP is also a security protocol used in wireless networks but less secure.|
|Network Time Protocol|	NTP|	It is used to synchronize the timing of computers on a network.|
|Virtual Local Area Network|	VLAN|	It is a way to segment a network into multiple logical networks.|
|VLAN Trunking Protocol|	VTP|	VTP is a Layer 2 protocol that is used to establish and maintain a virtual LAN (VLAN) spanning multiple switches.|
|Routing Information Protocol|	RIP|	RIP is a distance-vector routing protocol used in local area networks (LANs) and wide area networks (WANs).|
|Open Shortest Path First|	OSPF|	It is an interior gateway protocol (IGP) for routing traffic within a single Autonomous System (AS) in an Internet Protocol (IP) network.|
|Interior Gateway Routing Protocol|	IGRP|	IGRP is a Cisco proprietary interior gateway protocol designed for routing within autonomous systems.|
|Enhanced Interior Gateway Routing Protocol|	EIGRP|	It is an advanced distance-vector routing protocol that is used to route IP traffic within a network.|
|Pretty Good Privacy|	PGP|	PGP is an encryption program that is used to secure emails, files, and other types of data.|
|Network News Transfer Protocol|	NNTP|	NNTP is a protocol used for distributing and retrieving messages in newsgroups across the internet.|
|Cisco Discovery Protocol|	CDP	|It is a proprietary protocol developed by Cisco Systems that allows network administrators to discover and manage Cisco devices connected to the network.|
|Hot Standby Router Protocol|	HSRP|	HSRP is a protocol used in Cisco routers to provide redundancy in the event of a router or other network device failure.|
|Virtual Router Redundancy Protocol|	VRRP|	It is a protocol used to provide automatic assignment of available Internet Protocol (IP) routers to participating hosts.|
|Spanning Tree Protocol|	STP|	STP is a network protocol used to ensure a loop-free topology in Layer 2 Ethernet networks.|
|Terminal Access Controller Access-Control System|TACACS|	TACACS is a protocol that provides centralized authentication, authorization, and accounting for network access.|
|Session Initiation Protocol|	SIP|	It is a signaling protocol used for establishing and terminating real-time voice, video and multimedia sessions over an IP network.|
|Voice Over IP|	VOIP|	VOIP is a technology that allows for telephone calls to be made over the internet.|
|Extensible Authentication Protocol|	EAP|	EAP is a framework for authentication that supports multiple authentication methods, such as passwords, digital certificates, one-time passwords, and public-key authentication.|
|Lightweight Extensible Authentication Protocol|	LEAP|	LEAP is a proprietary wireless authentication protocol developed by Cisco Systems. It is based on the Extensible Authentication Protocol (EAP) used in the Point-to-Point Protocol (PPP).|
|Protected Extensible Authentication Protocol|	PEAP|	PEAP is a security protocol that provides an encrypted tunnel for wireless networks and other types of networks.|
|Systems Management Server|	SMS|	SMS is a systems management solution that helps organizations manage their networks, systems, and mobile devices.|
|Microsoft Baseline Security Analyzer|	MBSA|	It is a free security tool from Microsoft that is used to detect potential security vulnerabilities in Windows computers, networks, and systems.|
|Supervisory Control and Data Acquisition|	SCADA|	It is a type of industrial control system that is used to monitor and control industrial processes, such as those in manufacturing, power generation, and water and waste treatment.|
|Virtual Private Network|	VPN|	VPN is a technology that allows users to create a secure, encrypted connection to another network over the internet.|
|Internet Protocol Security|	IPsec	|IPsec is a protocol used to provide secure, encrypted communication over a network. It is commonly used in VPNs, or Virtual Private Networks, to create a secure tunnel between two devices.|
|Point-to-Point Tunneling Protocol|	PPTP|	It is a protocol used to create a secure, encrypted tunnel for remote access.|
|Network Address Translation|	NAT|	NAT is a technology that allows multiple devices on a private network to connect to the internet using a single public IP address. NAT works by translating the private IP addresses of devices on the network into a single public IP address, which is then used to connect to the internet.|
|Carriage Return Line Feed|	CRLF|	Combines two control characters to indicate the end of a line and a start of a new one for certain text file formats.|
|Asynchronous JavaScript and XML|	AJAX|	Web development technique that allows creating dynamic web pages using JavaScript and XML/JSON.|
|Internet Server Application Programming Interface|	ISAPI	|Allows to create performance-oriented web extensions for web servers using a set of APIs.|
|Uniform Resource Identifier|	URI|	It is a syntax used to identify a resource on the Internet.|
|Uniform Resource Locator|	URL|	Subset of URI that identifies a web page or another resource on the Internet, including the protocol and the domain name.|
|Internet Key Exchange	|IKE	|IKE is a protocol used to set up a secure connection between two computers. It is used in virtual private networks (VPNs) to provide authentication and encryption for data transmission, protecting the data from outside eavesdropping and tampering.|
|Generic Routing Encapsulation	|GRE	|This protocol is used to encapsulate the data being transmitted within the VPN tunnel.|
|Remote Shell|	RSH|	It is a program under Unix that allows executing commands and programs on a remote computer.|

TCP - is a connection-oriented protocol that establishes a virtual connection between two devices before transmitting data by using a Three-Way-Handshake. This connection is maintained until the data transfer is complete.

UDP - is a connectionless protocol, which means it does not establish a virtual connection before transmitting data. Instead, it sends the data packets to the destination without checking to see if they were received. Has faster speeds than TCP at the cost of reliability.

ICMP - is a protocol used by devices to communicate with each other on the Internet for various purposes, including error reporting and status information.

|ICMP Request Type|	Description|
|:-:|:-:|
|Echo Request|	This message tests whether a device is reachable on the network. When a device sends an echo request, it expects to receive an echo reply message. For example, the tools tracert (Windows) or traceroute (Linux) always send ICMP echo requests.|
|Timestamp Request|	This message determines the time on a remote device.|
|Address Mask Request|	This message is used to request the subnet mask of a device.|

|ICMP Message Type|	Description|
|:-:|:-:|
|Echo reply|	This message is sent in response to an echo request message.|
|Destination unreachable|	This message is sent when a device cannot deliver a packet to its destination.|
|Redirect|	A router sends this message to inform a device that it should send its packets to a different router.|
|time exceeded|	This message is sent when a packet has taken too long to reach its destination. When it exceeds the Time-To-Live (TTL) limit. Windows system TTL is 128 by default. |
|Parameter problem|	This message is sent when there is a problem with a packet's header.|
|Source quench|	This message is sent when a device receives packets too quickly and cannot keep up. It is used to slow down the flow of packets.|

|Time-To-Live (TTL) Defaults|Hops|
|:-:|:-:|
|Windows systems | 128|
|macOS and Linux systems| 64|
|Solaris| 255|

NOTE: TTL can be changed by the user, do not rely on these values to identify the OS type of a device.
