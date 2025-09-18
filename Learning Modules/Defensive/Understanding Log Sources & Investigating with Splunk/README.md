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
