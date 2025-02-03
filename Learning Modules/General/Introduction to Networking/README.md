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
