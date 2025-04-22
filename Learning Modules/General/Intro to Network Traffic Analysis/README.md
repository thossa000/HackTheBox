# Network Traffic Analysis
Network Traffic Analysis (NTA) can be described as the act of examining network traffic to characterize common ports and protocols utilized, establish a baseline for our environment, monitor and respond to threats, and ensure the greatest possible insight into our organization's network.
his process helps security specialists determine anomalies, including security threats in the network, early and effectively pinpoint threats. NTA uses cases include:

- Collecting real-time traffic within the network to analyze upcoming threats.
- Setting a baseline for day-to-day network communications.
- Identifying and analyzing traffic from non-standard ports, suspicious hosts, and issues with networking protocols such as HTTP errors, problems with TCP, or other networking misconfigurations.
- Detecting malware on the wire, such as ransomware, exploits, and non-standard interactions.
- NTA is also useful when investigating past incidents and during threat hunting.

# Common Traffic Analysis Tools
|Tool|	Description|
|:-:|:-:|
|tcpdump|	tcpdump is a command-line utility that, with the aid of LibPcap, captures and interprets network traffic from a network interface or capture file.|
|Tshark|	TShark is a network packet analyzer much like TCPDump. It will capture packets from a live network or read and decode from a file. It is the command-line variant of Wireshark.|
|Wireshark|	Wireshark is a graphical network traffic analyzer. It captures and decodes frames off the wire and allows for an in-depth look into the environment. It can run many different dissectors against the traffic to characterize the protocols and applications and provide insight into what is happening.|
|NGrep|	NGrep is a pattern-matching tool built to serve a similar function as grep for Linux distributions. The big difference is that it works with network traffic packets. NGrep understands how to read live traffic or traffic from a PCAP file and utilize regex expressions and BPF syntax. This tool shines best when used to debug traffic from protocols like HTTP and FTP.|
|tcpick|	tcpick is a command-line packet sniffer that specializes in tracking and reassembling TCP streams. The functionality to read a stream and reassemble it back to a file with tcpick is excellent.|
|Network Taps|	Taps (Gigamon, Niagra-taps) are devices capable of taking copies of network traffic and sending them to another place for analysis. These can be in-line or out of band. They can actively capture and analyze the traffic directly or passively by putting the original packet back on the wire as if nothing had changed.|
|Networking Span Ports|	Span Ports are a way to copy frames from layer two or three networking devices during egress or ingress processing and send them to a collection point. Often a port is mirrored to send those copies to a log server.|
|Elastic Stack|	The Elastic Stack is a culmination of tools that can take data from many sources, ingest the data, and visualize it, to enable searching and analysis of it.|
|SIEMS|	SIEMS (such as Splunk) are a central point in which data is analyzed and visualized. Alerting, forensic analysis, and day-to-day checks against the traffic are all use cases for a SIEM.|

## BPF Syntax
Many of the tools mentioned above have their syntax and commands to utilize, but one that is shared among them is Berkeley Packet Filter (BPF) syntax. BPF is a technology that enables a raw interface to read and write from the Data-Link layer. 

# NTA Workflow
### 1. Ingest Traffic
### 2. Reduce Noise by Filtering
Once we complete the initial capture, an attempt to filter out unnecessary traffic from our view can make analysis easier. (Broadcast and Multicast traffic, for example.)
### 3. Analyze and Explore
Look at specific hosts, protocols, even things as specific as flags set in the TCP header. The following questions will help us:

1. Is the traffic encrypted or plain text? Should it be?
2. Can we see users attempting to access resources to which they should not have access?
3. Are different hosts talking to each other that typically do not?

### 4. Detect and Alert
1. Are we seeing any errors? Is a device not responding that should be?
2. Use our analysis to decide if what we see is benign or potentially malicious.
3. Other tools like IDS and IPS can come in handy at this point. They can run heuristics and signatures against the traffic to determine if anything within is potentially malicious.

### 5. Fix and Monitor
If we make a change or fix an issue, we should continue to monitor the source for a time to determine if the issue has been resolved.

# TCP VS. UDP

|Characteristic|	TCP|	UDP|
|:-:|:-:|:-:|
|Transmission|	Connection-oriented|	Connectionless. Fire and forget.
|Connection Establishment|	TCP uses a three-way handshake to ensure that a connection is established.|	UDP does not ensure the destination is listening.
|Data Delivery|	Stream-based conversations|	packet by packet, the source does not care if the destination is active
|Receipt of data|	Sequence and Acknowledgement numbers are utilized to account for data.|	UDP does not care.
|Speed	|TCP has more overhead and is slower because of its built-in functions.|	UDP is fast but unreliable.

## TCP Three-way Handshake
1. The client sends a packet with the SYN flag set to on along with other negotiable options in the TCP header.

This is a synchronization packet. It will only be set in the first packet from host and server and enables establishing a session by allowing both ends to agree on a sequence number to start communicating with.
This is crucial for the tracking of packets. Along with the sequence number sync, many other options are negotiated in this phase to include window size, maximum segment size, and selective acknowledgments.

2. The server will respond with a TCP packet that includes a SYN flag set for the sequence number negotiation and an ACK flag set to acknowledge the previous SYN packet sent by the host.

The server will also include any changes to the TCP options it requires set in the options fields of the TCP header.

3. The client will respond with a TCP packet with an ACK flag set agreeing to the negotiation.

This packet is the end of the three-way handshake and established the connection between client and server.

When a connection concludes, TCP will use the following steps to gracefully close the connection. A flag we will see with TCP is the FIN flag. It is used for signaling that the data transfer is finished and the sender is requesting termination of the connection. The client acknowledges the receipt of the data and then sends a FIN and ACK to begin session termination. The server responds with an acknowledgment of the FIN and sends back its own FIN. Finally, the client acknowledges the session is complete and closes the connection. Before session termination, we should see a packet pattern of:

1. FIN, ACK
2. FIN, ACK,
3. ACK

## TCP Handshake in HTTPS

1. Client and server exchange hello messages to agree on connection parameters.
2. Client and server exchange necessary cryptographic parameters to establish a premaster secret.
3. Client and server will exchange x.509 certificates and cryptographic information allowing for authentication within the session.
4. Generate a master secret from the premaster secret and exchanged random values.
5. Client and server issue negotiated security parameters to the record layer portion of the TLS protocol.
6. Client and server verify that their peer has calculated the same security parameters and that the handshake occurred without tampering by an attacker.

# FTP Commands

|Command|	Description|
|:-:|:-:|
|USER|	specifies the user to log in as.
|PASS|	sends the password for the user attempting to log in.
|PORT| when in active mode, this will change the data port used.
|PASV|	switches the connection to the server from active mode to passive.
|LIST|	displays a list of the files in the current directory.
|CWD|	will change the current working directory to one specified.
|PWD|	prints out the directory you are currently working in.
|SIZE|	will return the size of a file specified.
|RETR|	retrieves the file from the FTP server.
|QUIT|	ends the session.

# The Analysis Process
Traffic Analysis is a detailed examination of an event or process, determining its origin and impact, which can be used to trigger specific precautions and/or actions to support or prevent future occurrences. With network traffic, this means breaking down the data into understandable chunks, examining it for anything that deviates from regular network traffic, for potentially malicious traffic such as unauthorized remote communications from the internet over RDP, SSH, or Telnet, or unique instances preceding network issues. 

Traffic capturing and analysis can be performed in two different ways, active or passive. With passive, we are just copying data that we can see without directly interacting with the packets. Active capture requires us to take a more hands-on approach. This process can also be referred to as in-line traffic captures. 

## Traffic Capture Dependencies
|Dependencies|	Passive|	Active|	Description|
|:-:|:-:|:-:|:-:|
|Permission|	☑|	☑|	Depending on the organization we are working in, capturing data can be against policy or even against the law in some sensitive areas like healthcare or banking. Be sure always to obtain permission in writing from someone with the proper authority to grant it to you. We may style ourselves as hackers, but we want to stay in the light legally and ethically.
|Mirrored Port|	☑|	☐|	A switch or router network interface configured to copy data from other sources to that specific interface, along with the capability to place your NIC into promiscuous mode. Having packets copied to our port allows us to inspect any traffic destined to the other links we could normally not have visibility over. Since VLANs and switch ports will not forward traffic outside of their broadcast domain, we have to be connected to the segment or have that traffic copied to our specific port. When dealing with wireless, passive can be a bit more complicated. We must be connected to the SSID we wish to capture traffic off of. Just passively listening to the airwaves around us will present us with many SSID broadcast advertisements, but not much else.
|Capture Tool|	☑|	☑|	A way to ingest the traffic. A computer with access to tools like TCPDump, Wireshark, Netminer, or others is sufficient. Keep in mind that when dealing with PCAP data, these files can get pretty large quickly. Each time we apply a filter to it in tools like Wireshark, it causes the application to parse that data again. This can be a resource-intensive process, so make sure the host has abundant resources.
|In-line Placement|	☐|	☑|	Placing a Tap in-line requires a topology change for the network you are working in. The source and destination hosts will not notice a difference in the traffic, but for the sake of routing and switching, it will be an invisible next hop the traffic passes through on its way to the destination.
|Network Tap or Host With Multiple NIC's|	☐|	☑|	A computer with two NIC's, or a device such as a Network Tap is required to allow the data we are inspecting to flow still. Think of it as adding another router in the middle of a link. To actively capture the traffic, we will be duplicating data directly from the sources. The best placement for a tap is in a layer three link between switched segments. It allows for the capture of any traffic routing outside of the local network. A switched port or VLAN segmentation does not filter our view here.
|Storage and Processing Power|	☑|	☑|	You will need plenty of storage space and processing power for traffic capture off a tap. Much more traffic is traversing a layer three link than just inside a switched LAN. Think of it like this; When we passively capture traffic inside a LAN, it's like pouring water into a cup from a water fountain. It's a steady stream but manageable. Actively grabbing traffic from a routed link is more like using a water hose to fill up a teacup. There is a lot more pressure behind the flow, and it can be a lot for the host to process and store.

# Analysis in Practice 

## Descriptive Analysis
Descriptive analysis is an essential step in any data analysis. It serves to describe a data set based on individual characteristics. It helps to detect possible errors in data collection and/or outliers in the data set.

1. What is the issue? - Suspected breach? Networking issue?
2. Define our scope and the goal. (what are we looking for? which time period?)
3. Define our target(s) (net / host(s) / protocol) - Scope: 192.168.100.0/24 network, protocols used were HTTP and FTP.

## Diagnostic Analysis
Diagnostic analysis clarifies the causes, effects, and interactions of conditions. 

4. Capture network traffic
5. Identification of required network traffic components (filtering)
6. An understanding of captured network traffic

## Predictive Analysis
By evaluating historical and current data, predictive analysis creates a predictive model for future probabilities. Based on the results of descriptive and diagnostic analyses, this method of data analysis makes it possible to identify trends, detect deviations from expected values at an early stage, and predict future occurrences as accurately as possible.

7. Note-taking and mind mapping of the found results
8. Summary of the analysis (what did we find?)

## Prescriptive Analysis
Prescriptive analysis aims to narrow down what actions to take to eliminate or prevent a future problem or trigger a specific activity or process. Using the results of our workflow, we can make sound decisions as to what actions are required to solve the problem and prevent it from happening again. To prescribe a solution is the culmination of this workflow. Once done and the problem is solved, it is prudent to reflect on the entire process and develop lessons learned.

Often this process is not a once-and-done kind of thing. It is usually cyclic, and we will need to rerun steps based on our analysis of the original capture to build a bigger picture.

## Key Components of an Effective Analysis

1. Know your environment
2. Placement is Key
3. Persistence

## Analysis Approach
Start with standard protocols first and work our way into the austere and specific only to the organization. Most attacks will come from the internet, so it has to access the internal net somehow. HTTP/S, FTP, E-mail, and basic TCP and UDP traffic will be the most common things seen coming from the world. Start at these and clear out anything that is not necessary to the investigation. 

After these, check standard protocols that allow for communications between networks, such as SSH, RDP, or Telnet. When looking for these types of anomalies, be mindful of the security policy of the network. Does our organization's security plan and implementations allow for RDP sessions that are initiated outside the enterprise? What about the use of Telnet?

Look for patterns. Is a specific host or set of hosts checking in with something on the internet at the same time daily? This is a typical Command and Control profile setup that can easily be spotted by looking for patterns in our traffic data. Check anything host to host within our network, typically hosts will talk to infrastructure for IP address leases, DNS requests, enterprise services and to find its route out. Look for unique events. 

# TCPDump Fundamentals
Tcpdump is a command-line packet sniffer that can directly capture and interpret data frames from a file or network interface. It was built for use on any Unix-like operating system and had a Windows twin called WinDump. To capture network traffic from "off the wire," it uses the libraries pcap and libpcap, paired with an interface in promiscuous mode to listen for data. 

### Basic Capture Options
These switches can be chained together to craft how the tool output is shown to us in STDOUT and what is saved to the capture file. This is not an exhaustive list, and there are many more we can use, but these are the most common and valuable.

|Switch Command|	Result|
|:-:|:-:|
|D|	Will display any interfaces available to capture from.
|i|	Selects an interface to capture from. ex. -i eth0
|n|	Do not resolve hostnames.
|nn|	Do not resolve hostnames or well-known ports.
|e|	Will grab the ethernet header along with upper-layer data.
|X|	Show Contents of packets in hex and ASCII.
|XX|	Same as X, but will also specify ethernet headers. (like using Xe)
|v, vv, vvv|	Increase the verbosity of output shown and saved.
|c|	Grab a specific number of packets, then quit the program.
|s|	Defines how much of a packet to grab.
|S|	change relative sequence numbers in the capture display to absolute sequence numbers. (13248765839 instead of 101)
|q|	Print less protocol information.
|r file.pcap|	Read from a file.
|w file.pcap|	Write into a file

# Tcpdump Packet Filtering
## Filtering and Advanced Syntax Options
### Helpful TCPDump Filters
|Filter|	Result|
|:-:|:-:|
|host|	host will filter visible traffic to show anything involving the designated host. Bi-directional
|src / dest|	src and dest are modifiers. We can use them to designate a source or destination host or port.
|net|	net will show us any traffic sourcing from or destined to the network designated. It uses / notation.
proto|	will filter for a specific protocol type. (ether, TCP, UDP, and ICMP as examples)
|port|	port is bi-directional. It will show any traffic with the specified port as the source or destination.
|portrange|	portrange allows us to specify a range of ports. (0-1024)
|less / greater "< >"|	less and greater can be used to look for a packet or protocol option of a specific size.
|and / &&	| and && can be used to concatenate two different filters together. for example, src host AND port.
|or|	or allows for a match on either of two conditions. It does not have to meet both. It can be tricky.
|not|	not is a modifier saying anything but x. For example, not UDP.

When utilizing filters, we can apply them directly to the capture or apply them when reading a capture file. By applying them to the capture, it will drop any traffic not matching the filter. When applying the filter to capture, we have read from a file, and the filter will parse the file and remove anything from our terminal output not matching the specified filter. It will not permanently change the capture file, and to change or clear the filter from our output will require we rerunning our command with a change in the syntax.

Using the -S switch will display absolute sequence numbers, which can be extremely long. Typically, tcpdump displays relative sequence numbers, which are easier to track and read. However, if we look for these values in another tool or log, we will only find the packet based on absolute sequence numbers.

The -v, -X, and -e switches can help you increase the amount of data captured, while the -c, -n, -s, -S, and -q switches can help reduce and modify the amount of data written and seen.

-A and -l switches: A will show only the ASCII text after the packet line, instead of both ASCII and Hex. L will tell tcpdump to output packets in a different mode. L will line buffer instead of pooling and pushing in chunks. It allows us to send the output directly to another tool such as grep using a pipe |.

# Tips For Analysis
Questions to ask ourselves when analyzing traffic:

- what type of traffic do you see? (protocol, port, etc.)
- Is there more than one conversation? (how many?)
- How many unique hosts?
- What is the timestamp of the first conversation in the pcap (tcp traffic)
- What traffic can I filter out to clean up my view?
- Who are the servers in the PCAP? (answering on well-known ports, 53, 80, etc.)
- What records were requested or methods used? (GET, POST, DNS A records, etc.)

# Analysis with Wireshark
Wireshark is a free and open-source network traffic analyzer much like tcpdump but with a graphical interface.

Features and Capabilities include:

- Deep packet inspection for hundreds of different protocols
- Graphical and TTY interfaces
- Capable of running on most Operating systems
- Ethernet, IEEE 802.11, PPP/HDLC, ATM, Bluetooth, USB, Token Ring, Frame Relay, FDDI, among others
- Decryption capabilities for IPsec, ISAKMP, Kerberos, SNMPv3, SSL/TLS, WEP, and WPA/WPA2

## TShark VS. Wireshark (Terminal vs. GUI)
TShark is perfect for use on machines with little or no desktop environment and can easily pass the capture information it receives to another tool via the command line. Wireshark is the feature-rich GUI option for traffic capture and analysis.

### Basic TShark Switches
|Switch Command|	Result|
|:-:|:-:|
|D|	Will display any interfaces available to capture from and then exit out.
|L|	Will list the Link-layer mediums you can capture from and then exit out. (ethernet as an example)
|i|	choose an interface to capture from. (-i eth0)
|f|	packet filter in libpcap syntax. Used during capture.
|c|	Grab a specific number of packets, then quit the program. Defines a stop condition.
|a|	Defines an autostop condition. Can be after a duration, specific file size, or after a certain number of packets.
|r| (pcap-file)	Read from a file.
|W| (pcap-file)	Write into a file using the pcapng format.
|P|	Will print the packet summary while writing into a file (-W)
|x|	will add Hex and ASCII output into the capture.
|h|	See the help menu.

### Wireshark GUI
![image](https://github.com/user-attachments/assets/f49a9ba7-81aa-4634-bc08-408431aabe87)
#### 1. Packet List: Orange

In this window, we see a summary line of each packet that includes the fields listed below by default. We can add or remove columns to change what information is presented.
- Number- Order the packet arrived in Wireshark
- Time- Unix time format
- Source- Source IP
- Destination- Destination IP
- Protocol- The protocol used (TCP, UDP, DNS, ETC.)
- Information- Information about the packet. This field can vary based on the type of protocol used within. It will show, for example, what type of query It is for a DNS packet.

#### 2. Packet Details: Blue

- The Packet Details window allows us to drill down into the packet to inspect the protocols with greater detail. It will break it down into chunks that we would expect following the typical OSI Model reference. The packet is dissected into different encapsulation layers for inspection.
- Wireshark will show this encapsulation in reverse order with lower layer encapsulation at the top of the window and higher levels at the bottom.

#### 3. Packet Bytes: Green

- The Packet Bytes window allows us to look at the packet contents in ASCII or hex output. As we select a field from the windows above, it will be highlighted in the Packet Bytes window and show us where that bit or byte falls within the overall packet.
- This is a great way to validate that what we see in the Details pane is accurate and the interpretation Wireshark made matches the packet output.
- Each line in the output contains the data offset, sixteen hexadecimal bytes, and sixteen ASCII bytes. Non-printable bytes are replaced with a period in the ASCII format.

### Pre-capture and Post-capture Processing and Filtering
We have several options regarding how and when we filter out traffic. This is accomplished utilizing Capture and Display filters. 

### Capture Filters
Capture Filters are entered before the capture is started. hese use BPF syntax like host 214.15.2.30 much the same as TCPDump. A capture filter will drop all other traffic not explicitly meeting the criteria set.

Useful Capture Filters:
|Capture Filters|	Result|
|:-:|:-:|
|host x.x.x.x|	Capture only traffic pertaining to a certain host
|net x.x.x.x/24|	Capture traffic to or from a specific network (using slash notation to specify the mask)
|src/dst net x.x.x.x/24|	Using src or dst net will only capture traffic sourcing from the specified network or destined to the target network
|port #|	will filter out all traffic except the port you specify
|not port #|	will capture everything except the port specified
|port # and #|	AND will concatenate your specified ports
|portrange x-x|	portrange will grab traffic from all ports within the range only
|ip / ether / tcp|	These filters will only grab traffic from specified protocol headers.
|broadcast / multicast / unicast|	Grabs a specific type of traffic. one to one, one to many, or one to all.

### Display Filters
Display Filters are used while the capture is running and after the capture has stopped. Display filters are proprietary to Wireshark.

Useful Capture Filters:
|Display Filters|	Result|
|:-:|:-:|
|ip.addr == x.x.x.x|	Capture only traffic pertaining to a certain host. This is an OR statement.
|ip.addr == x.x.x.x/24|	Capture traffic pertaining to a specific network. This is an OR statement.
|ip.src/dst == x.x.x.x|	Capture traffic to or from a specific host
|dns / tcp / ftp / arp / ip|	filter traffic by a specific protocol. There are many more options.
|tcp.port == x|	filter by a specific tcp port.
|tcp.port / udp.port != x|	will capture everything except the port specified
|and / or / not|	AND will concatenate, OR will find either of two options, NOT will exclude your input option.
