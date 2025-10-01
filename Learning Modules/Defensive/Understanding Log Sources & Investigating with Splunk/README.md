# Understanding Log Sources & Investigating with Splunk
Brief notes taken from the Understanding Log Sources & Investigating with Splunk module in HackTheBox Acedemy to study for the SOC Analyst exam.

## Introduction To Splunk & SPL
<img width="1006" height="402" alt="image" src="https://github.com/user-attachments/assets/61f417f8-7bc4-4cc4-bf6f-82c8c1b34340" />
<img width="1043" height="383" alt="image" src="https://github.com/user-attachments/assets/be600c46-8093-4174-8813-c5470da9eace" />

Splunk Enterprise architecture consists of several layers that work together to collect, index, search, analyze, and visualize data. The architecture can be divided into the following main components:

- Forwarders: Forwarders are responsible for data collection. They gather machine data from various sources and forward it to the indexers. The types of forwarders used in Splunk are:
- Universal Forwarder (UF): This is a lightweight agent that collects data and forwards it to the Splunk indexers without any preprocessing. Universal Forwarders are individual software packages that can be easily installed on remote sources without significantly affecting network or host performance.
- Heavy Forwarder (HF): This agent serves the purpose of collecting data from remote sources, especially for intensive data aggregation assignments involving sources like firewalls or data routing/filtering points. Heavy forwarders stand out from other types of forwarders as they parse data before forwarding, allowing them to route data based on specific criteria such as event source or type. They can also index data locally while simultaneously forwarding it to another indexer. Typically, Heavy Forwarders are deployed as dedicated "data collection nodes" for API/scripted data access, and they exclusively support Splunk Enterprise.

- Indexers: The indexers receive data from the forwarders, organize it, and store it in indexes. While indexing data, the indexers generate sets of directories categorized by age, wherein each directory hold compressed raw data and corresponding indexes that point to the raw data. They also process search queries from users and return results.
- Search Heads: Search heads coordinate search jobs, dispatching them to the indexers and merging the results. They also provide an interface for users to interact with Splunk. On Search Heads, Knowledge Objects can be crafted to extract supplementary fields and manipulate data without modifying the original index data.
- Deployment Server: It manages the configuration for forwarders, distributing apps and updates.
- Cluster Master: The cluster master coordinates the activities of indexers in a clustered environment, ensuring data replication and search affinity.
- License Master: It manages the licensing details of the Splunk platform.

Splunk's key components include:

- Splunk Web Interface: This is the graphical interface through which users can interact with Splunk, carrying out tasks like searching, creating alerts, dashboards, and reports.
- Search Processing Language (SPL): The query language for Splunk, allowing users to search, filter, and manipulate the indexed data.
- Knowledge Objects: These include fields, tags, event types, lookups, macros, data models, and alerts that enhance the data in Splunk, making it easier to search and analyze.
- Apps and Add-ons: Apps provide specific functionalities within Splunk, while add-ons extend capabilities or integrate with other systems. Splunk Apps enable the coexistence of multiple workspaces on a single Splunk instance, catering to different use cases and user roles. These ready-made apps can be found on Splunkbase, providing additional functionalities and pre-configured solutions. Splunk Technology Add-ons serve as an abstraction layer for data collection methods. They often include relevant field extractions, allowing for schema-on-the-fly functionality. Additionally, Technology Add-ons encompass pertinent configuration files (props/transforms) and supporting scripts or binaries. A Splunk App, on the other hand, can be seen as a comprehensive solution that typically utilizes one or more Technology Add-ons to enhance its capabilities.

Splunk as a SIEM solution can aid in real-time and historical data analysis, cybersecurity monitoring, incident response, and threat hunting. Moreover, it empowers organizations to enhance their detection capabilities by leveraging User Behavior Analytics.

## Basic Searching
By default, a search returns all events, but it can be narrowed down with keywords, boolean operators, comparison operators, and wildcard characters. 

By specifying the index as main, the query narrows down the search to only the events stored in the main index.
```
# This SPL query will search within the main index for events that contain the term UNKNOWN anywhere in the event data.
index="main" "*UNKNOWN*"
```
### Fields and Comparison Operators
The fields command specifies which fields should be included or excluded in the search results. Example:
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User
```

### table command
The table command presents search results in a tabular format. Example:
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image
```
_time is the timestamp of the event, host is the name of the host where the event occurred, and Image is the name of the executable file that represents the process.
### rename command
The rename command renames a field in the search results. Example:
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rename Image as Process
```
Image field in Sysmon logs represents the name of the executable file for the process. By renaming it, all the subsequent references to Process would now refer to what was originally the Image field.
### dedup command
The 'dedup' command removes duplicate events. Example:
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | dedup Image
```
### sort command
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort - _time
```
This command sorts all process creation events in the main index in descending order of their timestamps (_time), i.e., the most recent events are shown first.

### stats command
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | stats count by _time, Image
```
This query will return a table where each row represents a unique combination of a timestamp (_time) and a process (Image). The count column indicates the number of network connection events that occurred for that specific process at that specific time.

### chart command
The chart command creates a data visualization based on statistical operations. Example:
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | chart count by _time, Image
```
This query will return a table where each row represents a unique timestamp (_time) and each column represents a unique process (Image). The cell values indicate the number of network connection events that occurred for each process at each specific time.

### eval command
The eval command creates or redefines fields. Example:
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval Process_Path=lower(Image)
```
This command creates a new field Process_Path which contains the lowercase version of the Image field. It doesn't change the actual Image field, but creates a new field that can be used in subsequent operations or for display purposes.

### rex command
The rex command extracts new fields from existing ones using regular expressions. Example:
```
index="main" EventCode=4662 | rex max_match=0 "[^%](?<guid>{.*})" | table guid
```
rex max_match=0 "[^%](?<guid>{.*})" uses the rex command to extract values matching the pattern from the events' fields. The regex pattern {.*} looks for substrings that begin with { and end with }. The [^%] part ensures that the match does not begin with a % character. The captured value within the curly braces is assigned to the named capture group guid. The max_match=0 option ensures that all occurrences of the pattern are extracted from each event. By default, the rex command only extracts the first occurrence. table guid displays the extracted GUIDs in the output. This command is used to format the results and display only the guid field.

### lookup command
The lookup command enriches the data with external sources, like .csv files uploaded by the user to Splunk. Example:
<img width="1888" height="728" alt="image" src="https://github.com/user-attachments/assets/ca64a7c1-e259-4f62-8895-62a5dfbc9482" />
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rex field=Image "(?P<filename>[^\\\]+)$" | eval filename=lower(filename) | lookup malware_lookup.csv filename OUTPUTNEW is_malware | table filename, is_malware
```
- | rex field=Image "(?P<filename>[^\\\]+)$": This command is using the regular expression (regex) to extract a part of the Image field. The Image field in Sysmon EventCode=1 logs typically contains the full file path of the process. This regex is saying: Capture everything after the last backslash (which should be the filename itself) and save it as filename.
- | eval filename=lower(filename): This command is taking the filename that was just extracted and converting it to lowercase. The lower() function is used to ensure the search is case-insensitive.
- | lookup malware_lookup.csv filename OUTPUTNEW is_malware: This command is performing a lookup operation using the filename as a key. The lookup table (malware_lookup.csv) is expected to contain a list of filenames of known malicious executables. If a match is found in the lookup table, the new field is_malware is added to the event, which indicates whether or not the process is considered malicious based on the lookup table.
- | table filename, is_malware: This command is formatting the output to show only the fields filename and is_malware. If is_malware is not present in a row, it means that no match was found in the lookup table for that filename.

### inputlookup command
The inputlookup command retrieves data from a lookup file without joining it to the search results. Example:
```
| inputlookup malware_lookup.csv
```
This command retrieves all records from the malware_lookup.csv file. The result is not joined with any search results but can be used to verify the content of the lookup file or for subsequent operations like filtering or joining with other datasets.

### Time Range
Every event in Splunk has a timestamp. Using the time range picker or the earliest and latest commands, you can limit searches to specific time periods. Example:
```
index="main" earliest=-7d EventCode!=1
```
The query will retrieve events from the main index that occurred in the last seven days and do not have an EventCode value of 1.

### transaction command
The transaction command is used in Splunk to group events that share common characteristics into transactions, often used to track sessions or user activities that span across multiple events. Example:
```
index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3) | transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m | table Image |  dedup Image 
```
This query aims to identify sequences of activities (process creation followed by a network connection) associated with the same executable or script within a 1-minute window. It presents the results in a table format, ensuring that the listed executables/scripts are unique. The query can be valuable in threat hunting, particularly when looking for indicators of compromise such as rapid sequences of process creation and network connection events initiated by the same executable.
span
| transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m: The transaction command is used here to group events based on the Image field, which represents the executable or script involved in the event. This grouping is subject to the conditions: the transaction starts with an event where EventCode is 1 and ends with an event where EventCode is 3. The maxspan=1m clause limits the transaction to events occurring within a 1-minute window. The transaction command can link together related events to provide a better understanding of the sequences of activities happening within a system.

### Subsearches
A subsearch in Splunk is a search that is nested inside another search. It's used to compute a set of results that are then used in the outer search. Example:
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | top limit=100 Image | fields Image ] | table _time, Image, CommandLine, User, ComputerName
```
- NOT []: The square brackets contain the subsearch. By placing NOT before it, the main search will exclude any results that are returned by the subsearch.
- search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | top limit=100 Image | fields Image: The subsearch that fetches EventCode=1 (Process Creation) events, then uses the top command to return the 100 most common Image (process) names.
- table _time, Image, CommandLine, User, Computer: This presents the final results as a table, displaying the timestamp of the event (_time), the process name (Image), the command line used to execute the process (CommandLine), the user that executed the process (User), and the computer on which the event occurred (ComputerName).

This query can help to highlight unusual or rare processes, which may be worth investigating for potential malicious activity. Be sure to adjust the limit in the subsearch as necessary to fit your environment.

## How To Identify The Available Data
In Splunk, we primarily use the Search & Reporting application to do this. To identify the available source types, we can run the following SPL command, after selecting the suitable time range in the time picker of the Search & Reporting application.
```
| eventcount summarize=false index=* | table index
```
This query uses eventcount to count events in all indexes, then summarize=false is used to display counts for each index separately, the table command is used to present the data in tabular form.

```
| metadata type=sourcetypes index=* | table sourcetype
```
This search uses the metadata command, which provides us with various statistics about specified indexed fields. Here, we're focusing on sourcetypes. The result is a list of all sourcetypes in our Splunk environment, along with additional metadata such as the first time a source type was seen (firstTime), the last time it was seen (lastTime), and the number of hosts (totalCount).


```
| metadata type=sources index=* | table source
```

This command returns a list of all data sources in the Splunk environment.

Once we know our source types, we can investigate the kind of data they contain. Let's say we are interested in a sourcetype named WinEventLog:Security, we can use the table command to present the raw data as follows. This command will return the raw data for the specified source type.
```
sourcetype="WinEventLog:Security" | table _raw
```

Splunk automatically extracts a set of default fields for every event it indexes, but it can also extract additional fields depending on the source type of the data. To see all fields available in a specific source type, we can use the table command. This command generates a table with all fields available in the WinEventLog:Security sourcetype.
```
sourcetype="WinEventLog:Security" | table *
```

If we want to see a list of field names only, without the data, we can use the fieldsummary command instead.
```
sourcetype="WinEventLog:Security" | fieldsummary
```
This search will return a table that includes every field found in the events returned by the search (across the sourcetype we've specified). The table includes several columns of information about each field:

- field: The name of the field.
- count: The number of events that contain the field.
- distinct_count: The number of distinct values in the field.
- is_exact: Whether the count is exact or estimated.
- max: The maximum value of the field.
- mean: The mean value of the field.
- min: The minimum value of the field.
- numeric_count: The number of numeric values in the field.
- stdev: The standard deviation of the field.
- values: Sample values of the field.
- modes: The most common values of the field.
- numBuckets: The number of buckets used to estimate the distinct count.

Sometimes, we might want to know how events are distributed over time. This query retrieves all data (index=* sourcetype=*), then bucket command is used to group the events based on the _time field into 1-day buckets. The stats command then counts the number of events for each day (_time), index, and sourcetype. Lastly, the sort command sorts the result in descending order of _time.
```
index=* sourcetype=* | bucket _time span=1d | stats count by _time, index, sourcetype | sort - _time
```

The rare command can help us identify uncommon event types, which might be indicative of abnormal behavior. This query retrieves all data and finds the 10 rarest combinations of indexes and sourcetypes.
```
index=* sourcetype=* | rare limit=10 index, sourcetype
```

We can use the sistats command to explore event diversity. This command counts the number of events per index, sourcetype, source, and host, which can provide us a clear picture of the diversity and distribution of our data.
```
index=* | sistats count by index, sourcetype, source, host
```

Practice queries:
```
Finding account name with the highest amount of Kerberos authentication ticket requests.
index=* EventCode=4768 | stats count by Account_Name

Finding workstations that the System account logged into
index="main" sourcetype="WinEventLog:Security" EventCode=4624 
| stats dc(ComputerName) as Unique_Computers by Account_Name
| sort - Unique_Computers

Find account with the most logins in 10 minutes

index="main" sourcetype="WinEventLog:Security" EventCode=4624 
|  stats count, range(_time) as timerange by Account_Name
|  where timerange < 600 
|  sort count
```

### Using Splunk Applications
Splunk applications, or apps, are packages that we add to our Splunk Enterprise or Splunk Cloud deployments to extend capabilities and manage specific types of operational data. Apps can provide capabilities ranging from custom data inputs, custom visualizations, dashboards, alerts, reports, and more.

## Intrusion Detection With Splunk 
We start by targeting what we know is malicious from familiar data. Our first objective is to see what we can identify within the Sysmon data. We'll start by listing all our sourcetypes to approach this as an unknown environment from scratch. Run the following query to observe the possible sourcetypes:
```
index="main" | stats count by sourcetype
```

This will list all the sourcetypes available in your Splunk environment. Now let's query our Sysmon sourcetype and take a look at the incoming data.
```
index="main" sourcetype="WinEventLog:Sysmon"
```
Here we can verify that it is indeed Sysmon data and further identify extracted fields that we can target for searching. The extracted fields aid us in crafting more efficient searches. Targeted searches in your SIEM will execute and return results much more quickly. They also lessen resource consumption and allow your colleagues to use the SIEM with less disruption and impact. As we devise our queries to hunt anomalies, it's crucial that we keep crafting efficient queries at the forefront of our thinking, particularly if we aim to convert this query into an alert later.

```
index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode
```
Our scan uncovers 20 distinct EventCodes. Before we move further, let's remind ourselves of some of the Sysmon event descriptions and their potential usage in detecting malicious activity.

- Sysmon Event ID 1 - Process Creation: Useful for hunts targeting abnormal parent-child process hierarchies, as illustrated in the first lesson with Process Hacker. It's an event we can use later.
- Sysmon Event ID 2 - A process changed a file creation time: Helpful in spotting "time stomp" attacks, where attackers alter file creation times. Bear in mind, not all such actions signal malicious intent.
- Sysmon Event ID 3 - Network connection: A source of abundant noise since machines are perpetually establishing network connections. We may uncover anomalies, but let's consider other quieter areas first.
- Sysmon Event ID 4 - Sysmon service state changed: Could be a useful hunt if attackers attempt to stop Sysmon, though the majority of these events are likely benign and informational, considering Sysmon's frequent legitimate starts and stops.
- Sysmon Event ID 5 - Process terminated: This might aid us in detecting when attackers kill key processes or use sacrificial ones. For instance, Cobalt Strike often spawns temporary processes like werfault, the termination of which would be logged here, as well as the creation in ID 1.
- Sysmon Event ID 6 - Driver loaded: A potential flag for BYOD (bring your own driver) attacks, though this is less common. Before diving deep into this, let's weed out more conspicuous threats first.
- Sysmon Event ID 7 - Image loaded: Allows us to track dll loads, which is handy in detecting DLL hijacks.
- Sysmon Event ID 8 - CreateRemoteThread: Potentially aids in identifying injected threads. While remote threads can be created legitimately, if an attacker misuses this API, we can potentially trace their rogue process and what they injected into.
- Sysmon Event ID 10 - ProcessAccess: Useful for spotting remote code injection and memory dumping, as it records when handles on processes are made.
- Sysmon Event ID 11 - FileCreate: With many files being created frequently due to updates, downloads, etc., it might be challenging to aim our hunt directly here. However, these events can be beneficial in correlating or identifying a file's origins later.
- Sysmon Event ID 12 - RegistryEvent (Object create and delete) & Sysmon Event ID 13 - RegistryEvent (Value Set): While numerous events take place here, many registry events can be malicious, and with a good idea of what to look for, hunting here can be fruitful.
- Sysmon Event ID 15 - FileCreateStreamHash: Relates to file streams and the "Mark of the Web" pertaining to external downloads, but we'll leave this aside for now.
- Sysmon Event ID 16 - Sysmon config state changed: Logs alterations in Sysmon configuration, useful for spotting tampering.
- Sysmon Event ID 17 - Pipe created & Sysmon Event ID 18 - Pipe connected: Record pipe creations and connections. They can help observe malware's interprocess communication attempts, usage of PsExec, and SMB lateral movement.
- Sysmon Event ID 22 - DNSEvent: Tracks DNS queries, which can be beneficial for monitoring beacon resolutions and DNS beacons.
- Sysmon Event ID 23 - FileDelete: Monitors file deletions, which can provide insights into whether a threat actor cleaned up their malware, deleted crucial files, or possibly attempted a ransomware attack.
- Sysmon Event ID 25 - ProcessTampering (Process image change): Alerts on behaviors such as process herpadering, acting as a mini AV alert filter.

Based on these EventCodes, we can perform preliminary queries. As previously stated, unusual parent-child trees are always suspicious. Let's inspect all parent-child trees with this query.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | stats count by ParentImage, Image
```

Now target child processes known to be problematic, like cmd.exe or powershell.exe. Let's target these two.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") | stats count by ParentImage, Image
```

The notepad.exe to powershell.exe chain stands out immediately. It implies that notepad.exe was run, which then spawned a child powershell to execute a command. The next steps? Question the why and validate if this is typical.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") ParentImage="C:\\Windows\\System32\\notepad.exe"
```
We see the ParentCommandLine (just notepad.exe with no arguments) triggering a CommandLine of powershell.exe seemingly downloading a file from a server with the IP of 10.0.0.229!

We could investigate other machines interacting with this IP and assess its legitimacy. Let's unearth more about this IP by running some queries to explore all sourcetypes that could shed some light.
```
index="main" 10.0.0.229 | stats count by sourcetype
index="main" 10.0.0.229 sourcetype="linux:syslog"
```

Here we see that based on the data and the host parameter, we can conclude that this IP belongs to the host named waldo-virtual-machine on its ens160 interface. The IP seems to be doing some generic stuff. This finding indicates that our machine has engaged in some form of communication with a Linux system, notably downloading executable files through PowerShell. This sparks some concerns, hinting at the potential compromise of the Linux system as well! We're intrigued to dig deeper. So, let's initiate another inquiry using Sysmon data to unearth any further connections that might have been established.
```
index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine
```
We can spot several binaries with conspicuously malicious names, offering strong signals of their hostile intent. From our assessment, it's becoming increasingly clear that not only was the spawning of notepad.exe to powershell.exe malicious in nature, but the Linux system also appears to be infected. It seems to be instrumental in transmitting additional utilities. We can now fine-tune our search query to zoom in on the hosts executing these commands.
```
index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine, host
```
Our analysis indicates that two hosts fell prey to this Linux pivot. Notably, it appears that the DCSync PowerShell script was executed on the second host, indicating a likely DCSync attack.
```
index="main" EventCode=4662 Access_Mask=0x100 Account_Name!=*$
```
Now, let's dissect the rationale behind this query. Event Code 4662 is triggered when an Active Directory (AD) object is accessed. It's typically disabled by default and must be deliberately enabled by the Domain Controller to start appearing. Access Mask 0x100 specifically requests Control Access typically needed for DCSync's high-level permissions. The Account_Name checks where AD objects are directly accessed by users instead of accounts, as DCSync should only be performed legitimately by machine accounts or SYSTEM, not users. You might be wondering how we can ascertain these are DCSync attempts since they could be accessing anything. To address this, we evaluate based on the properties field.
<img width="730" height="180" alt="image" src="https://github.com/user-attachments/assets/33721676-d427-47d1-a091-f56ed98400fe" />

Upon researching, we find that the first one is linked to DS-Replication-Get-Changes-All, which, as per its description, "...allows the replication of secret domain data".

This gives us solid confirmation that a DCSync attempt was made and successfully executed by the Waldo user on the UNIWALDO domain. It's reasonable to presume that the Waldo user either possesses Domain Admin rights or has a certain level of access rights permitting this action. Furthermore, it's highly likely that the attacker has extracted all the accounts within the AD as well! This signifies a full compromise in our network, and we should consider rotating our krbtgt just in case a golden ticket was created.

The attacker must have initially infiltrated the system and undertaken several maneuvers to obtain domain admin rights, orchestrate lateral movement, and dump the domain credentials. Sysmon event code 10 can provide us with data on process access or processes opening handles to other processes. We'll deploy the following query to zero in on potential lsass dumping.
```
index="main" EventCode=10 lsass | stats count by SourceImage
```
We prefer sorting by count to make the data more comprehensible. While it's not always safe to make assumptions, it's generally accepted that an activity occurring frequently is "normal" in an environment. It's also harder to detect malicious activity in a sea of 99 events compared to spotting it in just 1 or 5 possible events. With this logic, we'll begin by examining any conspicuous strange process accesses to lsass.exe by any source image. The most noticeable ones are notepad (given its absurdity) and rundll32 (given its limited frequency). We can further explore these as we usually do.
```
index="main" EventCode=10 lsass SourceImage="C:\\Windows\\System32\\notepad.exe"
```
## Detecting Attacker Behavior With Splunk Based On TTPs
In crafting detection-related SPL (Search Processing Language) searches in Splunk, we utilize two main approaches:

- The first approach is grounded in known adversary TTPs, leveraging our extensive knowledge of specific threats and attack vectors. This strategy is akin to playing a game of spot the known. If an entity behaves in a way that we recognize as characteristic of a particular threat, it draws our attention.

- The second approach, while still informed by an understanding of attacker TTPs, leans heavily on statistical analysis and anomaly detection to identify abnormal behavior within the sea of normal activity. This strategy is more of a game of spot the unusual. Here, we're not just relying on pre-existing knowledge of specific threats. Instead, we make extensive use of mathematical and statistical techniques to highlight anomalies, working on the premise that malicious activity will often manifest as an aberration from the norm.

Additionally, in both approaches, the key is to understand our data and environment, then carefully tune our queries and thresholds to balance the need for accurate detection with the desire to avoid false positives. Through continuous review and revision of our SPL queries, we can maintain a high level of security posture and readiness.

### Crafting SPL Searches Based On Known TTPs
1. Example: Detection Of Reconnaissance Activities Leveraging Native Windows Binaries
   Attackers often leverage native Windows binaries (such as net.exe) to gain insights into the target environment, identify potential privilege escalation opportunities, and perform lateral movement. Sysmon Event ID 1 can assist in identifying such behavior.

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe | stats count by Image,CommandLine | sort - count
```
Within the search results, clear indications emerge, highlighting the utilization of native Windows binaries for reconnaissance purposes.

2. Example: Detection Of Requesting Malicious Payloads/Tools Hosted On Reputable/Whitelisted Domains (Such As githubusercontent.com)
Attackers frequently exploit the use of githubusercontent.com as a hosting platform for their payloads. This is due to the common whitelisting and permissibility of the domain by company proxies. Sysmon Event ID 22 can assist in identifying such behavior.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=22  QueryName="*github*" | stats count by Image, QueryName
```
Within the search results, clear indications emerge, highlighting the utilization of githubusercontent.com for payload/tool-hosting purposes.

3. Example: Detection Of PsExec Usage
The very features that make PsExec a powerful tool for system administrators also make it an attractive option for malicious actors. Several MITRE ATT&CK techniques, including T1569.002 (System Services: Service Execution), T1021.002 (Remote Services: SMB/Windows Admin Shares), and T1570 (Lateral Tool Transfer), have seen PsExec in play. It works by copying a service executable to the hidden Admin$ share. Subsequently, it taps into the Windows Service Control Manager API to jump-start the service. The service uses named pipes to link back to the PsExec tool. A major highlight is that PsExec can be deployed on both local and remote machines, and it can enable a user to act under the NT AUTHORITY\SYSTEM account.

Sysmon Event ID 13, Sysmon Event ID 11, and Sysmon Event ID 17 or Sysmon Event ID 18 can assist in identifying usage of PsExec.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath" | rex field=Details "(?<reg_file_name>[^\\\]+)$" | eval reg_file_name = lower(reg_file_name), file_name = if(isnull(file_name),reg_file_name,lower(file_name)) | stats values(Image) AS Image, values(Details) AS RegistryDetails, values(_time) AS EventTimes, count by file_name, ComputerName

index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System | stats count by TargetFilename

index="main" sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System | stats count by PipeName
```

4. Example: Detection Of Utilizing Archive Files For Transferring Tools Or Data Exfiltration
Attackers may employ zip, rar, or 7z files for transferring tools to a compromised host or exfiltrating data from it. The following search examines the creation of zip, rar, or 7z files, with results sorted in descending order based on count.
```
index="main" EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z") | stats count by ComputerName, User, TargetFilename | sort - count
```
Within the search results, clear indications emerge, highlighting the usage of archive files for tool-transferring and/or data exfiltration purposes.

5. Example: Detection Of Utilizing PowerShell or MS Edge For Downloading Payloads/Tools
Attackers may exploit PowerShell to download additional payloads and tools, or deceive users into downloading malware via web browsers. The following SPL searches examine files downloaded through PowerShell or MS Edge.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*powershell.exe*" |  stats count by Image, TargetFilename |  sort + count

index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*msedge.exe" TargetFilename=*"Zone.Identifier" |  stats count by TargetFilename |  sort + count
```
The *Zone.Identifier is indicative of a file downloaded from the internet or another potentially untrustworthy source. Windows uses this zone identifier to track the security zones of a file. The Zone.Identifier is an ADS (Alternate Data Stream) that contains metadata about where the file was downloaded from and its security settings.

6. Example: Detection Of Execution From Atypical Or Suspicious Locations
   The following SPL search is designed to identify any process creation (EventCode=1) occurring in a user's Downloads folder.
```
index="main" EventCode=1 | regex Image="C:\\\\Users\\\\.*\\\\Downloads\\\\.*" |  stats count by Image
```
Within the less frequent search results, clear indications emerge, highlighting execution from a user's Downloads folder.

7. Example: Detection Of Executables or DLLs Being Created Outside The Windows Directory
The following SPL identifies potential malware activity by checking for the creation of executable and DLL files outside the Windows directory. It then groups and counts these activities by user and target filename.
```
index="main" EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll") TargetFilename!="*\\windows\\*" | stats count by User, TargetFilename | sort + count
```

8. Example: Detection Of Misspelling Legitimate Binaries
Attackers often disguise their malicious binaries by intentionally misspelling legitimate ones to blend in and avoid detection. The purpose of the following SPL search is to detect potential misspellings of the legitimate PSEXESVC.exe binary, commonly used by PsExec. By examining the Image, ParentImage, CommandLine and ParentCommandLine fields, the search aims to identify instances where variations of psexe are used, potentially indicating the presence of malicious binaries attempting to masquerade as the legitimate PsExec service binary.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (CommandLine="*psexe*.exe" NOT (CommandLine="*PSEXESVC.exe" OR CommandLine="*PsExec64.exe")) OR (ParentCommandLine="*psexe*.exe" NOT (ParentCommandLine="*PSEXESVC.exe" OR ParentCommandLine="*PsExec64.exe")) OR (ParentImage="*psexe*.exe" NOT (ParentImage="*PSEXESVC.exe" OR ParentImage="*PsExec64.exe")) OR (Image="*psexe*.exe" NOT (Image="*PSEXESVC.exe" OR Image="*PsExec64.exe")) |  table Image, CommandLine, ParentImage, ParentCommandLine
```

9. Example: Detection Of Using Non-standard Ports For Communications/Transfers
   Attackers often utilize non-standard ports during their operations. The following SPL search detects suspicious network connections to non-standard ports by excluding standard web and file transfer ports (80, 443, 22, 21). The stats command aggregates these connections, and they are sorted in descending order by count.
```
index="main" EventCode=3 NOT (DestinationPort=80 OR DestinationPort=443 OR DestinationPort=22 OR DestinationPort=21) | stats count by SourceIp, DestinationIp, DestinationPort | sort - count
```

## Detecting Attacker Behavior With Splunk Based On Analytics
By profiling normal behavior and identifying deviations from this baseline, we can uncover suspicious activities that may signify an intrusion. A good example of this approach in Splunk is the use of the streamstats command. This command allows us to perform real-time analytics on the data, which can be useful for identifying unusual patterns or trends.

Consider a scenario where we are monitoring the number of network connections initiated by a process within a certain time frame.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | bin _time span=1h | stats count as NetworkConnections by _time, Image | streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image | eval isOutlier=if(NetworkConnections > (avg + (0.5*stdev)), 1, 0) | search isOutlier=1
```
- We start by focusing on network connection events (EventCode=3), and then group these events into hourly intervals (bin can be seen as a bucket alias). For each unique process image (Image), we calculate the number of network connection events per time bucket.
- We then use the streamstats command to calculate a rolling average and standard deviation of the number of network connections over a 24-hour period for each unique process image. This gives us a dynamic baseline to compare each data point to.
- The eval command is then used to create a new field, isOutlier, and assigns it a value of 1 for any event where the number of network connections is more than 0.5 standard deviations away from the average. This labels these events as statistically anomalous and potentially indicative of suspicious activity.
- Lastly, the search command filters our results to only include the outliers, i.e., the events where isOutlier equals 1.

### Crafting SPL Searches Based On Analytics
1. Example: Detection Of Abnormally Long Commands
Attackers frequently employ excessively long commands as part of their operations to accomplish their objectives.
```
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe | eval len=len(CommandLine) | table User, len, CommandLine | sort - len
```

2. Example: Detection Of Abnormal cmd.exe Activity
The following search identifies unusual cmd.exe activity within a certain time range. It uses the bucket command to group events by hour, calculates the count, average, and standard deviation of cmd.exe executions, and flags outliers.

```
index="main" EventCode=1 (CommandLine="*cmd.exe*") | bucket _time span=1h | stats count as cmdCount by _time User CommandLine | eventstats avg(cmdCount) as avg stdev(cmdCount) as stdev | eval isOutlier=if(cmdCount > avg+1.5*stdev, 1, 0) | search isOutlier=1
```

3. Example: Detection Of Processes Loading A High Number Of DLLs In A Specific Time
It is not uncommon for malware to load multiple DLLs in rapid succession. The following SPL can assist in monitoring this behavior.
```
index="main" EventCode=7 NOT (Image="C:\\Windows\\System32*") NOT (Image="C:\\Program Files (x86)*") NOT (Image="C:\\Program Files*") NOT (Image="C:\\ProgramData*") NOT (Image="C:\\Users\\waldo\\AppData*")| bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded | sort - unique_dlls_loaded
```

4. Example: Detection Of Processes Loading A High Number Of DLLs In A Specific Time
It is not uncommon for malware to load multiple DLLs in rapid succession. The following SPL can assist in monitoring this behavior.
```
index="main" EventCode=7 | bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded

index="main" EventCode=7 NOT (Image="C:\\Windows\\System32*") NOT (Image="C:\\Program Files (x86)*") NOT (Image="C:\\Program Files*") NOT (Image="C:\\ProgramData*") NOT (Image="C:\\Users\\waldo\\AppData*")| bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded | sort - unique_dlls_loaded
```

5. Example: Detection Of Transactions Where The Same Process Has Been Created More Than Once On The Same Computer
We want to correlate events where the same process (Image) is executed on the same computer (ComputerName) since this might indicate abnormalities depending on the nature of the processes involved. As always, context and additional investigation would be necessary to confirm if it's truly malicious or just a benign occurrence. The following SPL can assist in monitoring this behavior.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | transaction ComputerName, Image | where mvcount(ProcessGuid) > 1 | stats count by Image, ParentImage
```


