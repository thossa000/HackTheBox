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
![image](https://github.com/user-attachments/assets/d745d44a-c5a8-42b4-89cf-882c31685155)
