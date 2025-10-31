# Working with IDS/IPS
Brief notes on the HackTheBox Academy module, Working with IDS/IPS, in the SOC Analyst learning path.

## Suricata Fundamentals
### Suricata Operation Modes

Suricata operates in four (4) distinct modes:

1. The Intrusion Detection System (IDS) mode positions Suricata as a silent observer. In this capacity, Suricata meticulously examines traffic, flagging potential attacks but refraining from any form of intervention. By providing an in-depth view of network activities and accelerating response times, this mode augments network visibility, albeit without offering direct protection.
2. In the Intrusion Prevention System (IPS) mode, Suricata adopts a proactive stance. All network traffic must pass through Suricata's stringent checks and is only granted access to the internal network upon Suricata's approval. This mode bolsters security by proactively thwarting attacks before they penetrate our internal network. Deploying Suricata in IPS mode demands an intimate understanding of the network landscape to prevent the inadvertent blocking of legitimate traffic. Furthermore, each rule activation necessitates rigorous testing and validation. While this mode enhances security, the inspection process may introduce latency.
3. The Intrusion Detection Prevention System (IDPS) mode brings together the best of both IDS and IPS. While Suricata continues to passively monitor traffic, it possesses the ability to actively transmit RST packets in response to abnormal activities. This mode strikes a balance between active protection and maintaining low latency, crucial for seamless network operations.
4. In its Network Security Monitoring (NSM) mode, Suricata transitions into a dedicated logging mechanism, eschewing active or passive traffic analysis or prevention capabilities. It meticulously logs every piece of network information it encounters, providing a valuable wealth of data for retrospective security incident investigations, despite the high volume of data generated.

### Configuring Suricata & Custom Rules
```
thossa00@htb[/htb]$ ls -lah /etc/suricata/rules/
```
Rules might be commented out, meaning they aren't loaded and don't affect the system. This usually happens when a new version of the rule comes into play or if the threat associated with the rule becomes outdated or irrelevant.

Each rule usually involves specific variables, such as $HOME_NET and $EXTERNAL_NET. The rule examines traffic from the IP addresses specified in the $HOME_NET variable heading towards the IP addresses in the $EXTERNAL_NET variable.

These variables can be defined in the suricata.yaml configuration file.
```
thossa00@htb[/htb]$ more /etc/suricata/suricata.yaml
```
Finally, to configure Suricata to load signatures from a custom rules file, such as local.rules in the /home/htb-student directory, we would execute the below.
```
thossa00@htb[/htb]$ sudo vim /etc/suricata/suricata.yaml
```

### Suricata Outputs
Suricata records a variety of data into logs that reside in the /var/log/suricata directory by default. For us to access and manipulate these logs, we require root-level access. Among these logs, we find the eve.json, fast.log, and stats.log files, which provide invaluable insight into the network activity. Let's delve into each:

1. eve.json: This file is Suricata's recommended output and contains JSON objects, each carrying diverse information such as timestamps, flow_id, event_type, and more. Try inspecting the content of old_eve.json residing at /var/log/suricata as follows.

If we wish to filter out only alert events, for example, we can utilize the jq command-line JSON processor as follows.

```
thossa00@htb[/htb]$ cat /var/log/suricata/old_eve.json | jq -c

# If we wish to identify the earliest DNS event, for example, we can utilize the jq command-line JSON processor as follows.

thossa00@htb[/htb]$ cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "dns")' | head -1 | jq .
```

2. fast.log: This is a text-based log format that records alerts only and is enabled by default. Try inspecting the content of old_fast.log residing at /var/log/suricata as follows.

```
thossa00@htb[/htb]$ cat /var/log/suricata/old_fast.log
```

3. stats.log: This is a human-readable statistics log, which can be particularly useful while debugging Suricata deployments.

Suricata Key Features
Key features that bolster Suricata's effectiveness include:

- Deep packet inspection and packet capture logging
- Anomaly detection and Network Security Monitoring
- Intrusion Detection and Prevention, with a hybrid mode available
- Lua scripting
- Geographic IP identification (GeoIP)
- Full IPv4 and IPv6 support
- IP reputation
- File extraction
- Advanced protocol inspection
- Multitenancy

### Activity 1
```
thossa00@htb[/htb]$ cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "http")' | head -1 | jq .

root@ubuntu: vim /etc/suricata/suricata.yaml

enable http-log on line 307

root@ubuntu:/etc/suricata/rules# suricata-update
root@ubuntu:/etc/suricata/rules# suricata -r /home/htb-student/pcaps/suspicious.pcap
root@ubuntu:/etc/suricata/rules# cd /var/log/suricata
root@ubuntu:/var/log/suricata# cat http.log
```

### Suricata Rule Development
Samplee rule:
```
action protocol from_ip port -> to_ip port (msg:"Known malicious behavior, possible X malware infection"; content:"some thing"; content:"some other thing"; sid:10000001; rev:1;)
```
### Rule Development (Encrypted Traffic)
SSL/TLS certificates, exchanged during the initial handshake of an SSL/TLS connection, contain a plethora of details that remain unencrypted. These details can include the issuer, the issue date, the expiry date, and the subject (containing information about who the certificate is for and the domain name). Suspicious or malicious domains might utilize SSL/TLS certificates with anomalous or unique characteristics. Recognizing these anomalies in SSL/TLS certificates can be a stepping stone to crafting effective Suricata rules.

Further, we can also utilize the JA3 hash — a fingerprinting method that provides a unique representation for each SSL/TLS client. The JA3 hash combines details from the client hello packet during the SSL/TLS handshake, creating a digest that could be unique for specific malware families or suspicious software.

```
alert tls any any -> any any (msg:"Sliver C2 SSL"; ja3.hash; content:"473cd7cb9faa642487833865d516e578"; sid:1002; rev:1;)

# The Suricata rule above is designed to detect certain variations of Sliver whenever it identifies a TLS connection with a specific JA3 hash.
```
Reading JA3 hash digest for pcap files to create Suricata rules:
```
ja3 -a --json /home/htb-student/pcaps/sliverenc.pcap
```
## Snort Fundamentals
Snort Operation Modes:

- Inline IDS/IPS - give Snort the ability to block traffic if a particular packet warrants such an event.
- Passive IDS - gives Snort the ability to observe and detect traffic on a network interface, but it prevents outright blocking of traffic.
- Network-based IDS
- Host-based IDS (however, Snort is not ideally a host-based IDS. We would recommend opting for more specialized tools for this.)

Snort will infer the particular mode of operation based on the options used at the command line. For example, reading from a pcap file with the -r option or listening on an interface with -i will cause Snort to run in passive mode by default. If the DAQ supports inline, however, then users can specify the -Q flag to run Snort inline. One DAQ module that supports inline mode is afpacket, which is a module that gives Snort access to packets received on Linux network devices.

### Snort Architecture
In order for Snort to transition from a simple packet sniffer to a robust IDS, several key components were added: Preprocessor, Detection Engine, Logging and Alerting System, and various Output modules.

- The packet sniffer (which includes the Packet Decoder) extracts network traffic, recognizing the structure of each packet. The raw packets that are collected are subsequently forwarded to the Preprocessors.
- Preprocessors within Snort identify the type or behaviour of the forwarded packets. Snort has an array of Preprocessor plugins, like the HTTP plugin that distinguishes HTTP-related packets or the port_scan Preprocessor which identifies potential port scanning attempts based on predefined protocols, types of scans, and thresholds. After the Preprocessors have completed their task, information is passed to the Detection Engine. The configuration of these Preprocessors can be found within the Snort configuration file, snort.lua.
- The Detection Engine compares each packet with a predefined set of Snort rules. If a match is found, information is forwarded to the Logging and Alerting System.
- The Logging and Alerting System and Output modules are in charge of recording or triggering alerts as determined by each rule action. Logs are generally stored in syslog or unified2 formats or directly in a database. The Output modules are configured within the Snort configuration file, snort.lua.

### Snort Configuration & Validating Snort's Configuration
Snort 3 provides users with pre-configured files to facilitate a quick start. These default configuration files, namely snort.lua (principal configuration file) and snort_defaults.lua:

- Network variables
- Decoder configuration
- Base detection engine configuration
- Dynamic library configuration
- Preprocessor configuration
- Output plugin configuration
- Rule set customization
- Preprocessor and decoder rule set customization
- Shared object rule set customization

Use 'snort --help-modules' for help with enabling and tuning Snort modules.

These modules are enabled and configured within the snort.lua configuration file as Lua table literals. If a module is initialized as an empty table, it implies that it is utilizing its predefined "default" settings. To view these default settings, you can utilize the following command.

```
thossa00@htb[/htb]$ snort --help-config arp_spoof
```
Passing (and validating) configuration files to Snort can be done as follows.
```
thossa00@htb[/htb]$ snort -c /root/snorty/etc/snort/snort.lua --daq-dir

# Note: --daq-dir /usr/local/lib/daq is not required to pass and validate a configuration file. It is added so that we can replicate the command in this section's target.
```

### Snort Inputs
By providing the name of the pcap file as an argument to the -r option in the command line, Snort will process the file accordingly.
```
thossa00@htb[/htb]$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap
```

Snort also has the capability to listen on active network interfaces. To specify this behavior, you can utilize the -i option followed by the names of the interfaces on which Snort should run.
```
thossa00@htb[/htb]$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -i ens160
```

### Snort Rules
Snort rules, which resemble Suricata rules, are composed of a rule header and rule options. The most recent Snort rules can be obtained from the Snort website or the Emerging Threats website.

In Snort deployments, we have flexibility in managing rules. It's possible to place rules (for example, local.rules residing at /home/htb-student) directly within the snort.lua configuration file using the ips module as follows.
```
thossa00@htb[/htb]$ sudo vim /root/snorty/etc/snort/snort.lua

----SNIP----
ips =
{
    -- use this to enable decoder and inspector alerts
    --enable_builtin_rules = true,

    -- use include for rules files; be sure to set your path
    -- note that rules files can include other rules files
    -- (see also related path vars at the top of snort_defaults.lua)

    { variables = default_variables, include = '/home/htb-student/local.rules' }
}
```
Then, the "included" rules will be automatically loaded.

Alternatively we can load snort rules from the terminal:
- For a single rules file, we can use the -R option followed by the path to the rules file. This allows us to specify a specific rules file to be utilized by Snort.
- To include an entire directory of rules files, we can use the --rule-path option followed by the path to the rules directory. This enables us to provide Snort with a directory containing multiple rules files.

### Snort Outputs






## Zeek Fundamentals
### Zeek's Operation Modes
Zeek operates in the following modes:

- Fully passive traffic analysis
- libpcap interface for packet capture
- Real-time and offline (e.g., PCAP-based) analysis
- Cluster support for large-scale deployments

### Zeek's Architecture
Zeek's architecture comprises two primary components: the event engine (or core) and the script interpreter.

The event engine takes an incoming packet stream and transforms it into a series of high-level events. In Zeek's context, these events describe network activity in policy-neutral terms, meaning they inform us of what's happening, but they don't offer an interpretation or evaluation of it.

Such interpretation or analysis is provided by Zeek's script interpreter, which executes a set of event handlers written in Zeek's scripting language (Zeek scripts). These scripts express the site's security policy, defining actions to be taken upon the detection of certain events.

Events generated by Zeek's core are queued in an orderly manner, awaiting their turn to be processed on a first-come, first-served basis. Most of Zeek's events are defined in .bif files located in the /scripts/base/bif/plugins/ directory.

### Zeek Logs
Among the diverse array of logs Zeek produces, some familiar ones include:

- conn.log: This log provides details about IP, TCP, UDP, and ICMP connections.
- dns.log: Here, you'll find the details of DNS queries and responses.
- http.log: This log captures the details of HTTP requests and responses.
- ftp.log: Details of FTP requests and responses are logged here.
- smtp.log: This log covers SMTP transactions, such as sender and recipient details.

It's noteworthy to mention that Zeek, in its standard configuration, applies gzip compression to log files every hour. The older logs are then transferred into a directory named in the YYYY-MM-DD format. When dealing with these compressed logs, alternative tools like gzcat for printing logs or zgrep for searching within logs can come in handy. However, Zeek also provides a specialized tool known as zeek-cut for handling log files. This utility accepts Zeek log files via standard input using pipelines or stream redirections and then delivers the specified columns to the standard output.
