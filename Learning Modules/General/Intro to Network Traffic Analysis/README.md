# Network Traffic Analysis
Network Traffic Analysis (NTA) can be described as the act of examining network traffic to characterize common ports and protocols utilized, establish a baseline for our environment, monitor and respond to threats, and ensure the greatest possible insight into our organization's network.
his process helps security specialists determine anomalies, including security threats in the network, early and effectively pinpoint threats. NTA uses cases include:

- Collecting real-time traffic within the network to analyze upcoming threats.
- Setting a baseline for day-to-day network communications.
- Identifying and analyzing traffic from non-standard ports, suspicious hosts, and issues with networking protocols such as HTTP errors, problems with TCP, or other networking misconfigurations.
- Detecting malware on the wire, such as ransomware, exploits, and non-standard interactions.
- NTA is also useful when investigating past incidents and during threat hunting.

## Common Traffic Analysis Tools
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

### BPF Syntax
Many of the tools mentioned above have their syntax and commands to utilize, but one that is shared among them is Berkeley Packet Filter (BPF) syntax. BPF is a technology that enables a raw interface to read and write from the Data-Link layer. 

## NTA Workflow
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

## TCP VS. UDP

|Characteristic|	TCP|	UDP|
|:-:|:-:|:-:|
|Transmission|	Connection-oriented|	Connectionless. Fire and forget.
|Connection Establishment|	TCP uses a three-way handshake to ensure that a connection is established.|	UDP does not ensure the destination is listening.
|Data Delivery|	Stream-based conversations|	packet by packet, the source does not care if the destination is active
|Receipt of data|	Sequence and Acknowledgement numbers are utilized to account for data.|	UDP does not care.
|Speed	|TCP has more overhead and is slower because of its built-in functions.|	UDP is fast but unreliable.

### TCP Three-way Handshake
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

### TCP Handshake in HTTPS

1. Client and server exchange hello messages to agree on connection parameters.
2. Client and server exchange necessary cryptographic parameters to establish a premaster secret.
3. Client and server will exchange x.509 certificates and cryptographic information allowing for authentication within the session.
4. Generate a master secret from the premaster secret and exchanged random values.
5. Client and server issue negotiated security parameters to the record layer portion of the TLS protocol.
6. Client and server verify that their peer has calculated the same security parameters and that the handshake occurred without tampering by an attacker.

## FTP Commands

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

## The Analysis Process
